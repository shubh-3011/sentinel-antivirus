package com.shubh3011.sentinel.antivirus;

import com.shubh3011.sentinel.model.ScanResult;
import com.shubh3011.sentinel.model.Severity;
import com.shubh3011.sentinel.model.Threat;
import com.shubh3011.sentinel.model.ThreatSignature;
import com.shubh3011.sentinel.model.ThreatSignature.Type;
import com.shubh3011.sentinel.model.Verdict;
import com.shubh3011.sentinel.util.Hashing;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Static file analyser combining a signature database with behavioural heuristics.
 *
 * <p>Detection layers, cheapest first:
 * <ol>
 *   <li><b>Hash reputation</b> — exact SHA-256 match against known-bad digests.</li>
 *   <li><b>Content signatures</b> — literal and regex rules over the file bytes.</li>
 *   <li><b>Heuristics</b> — high entropy (packing/encryption), double extensions and
 *       executables masquerading behind document extensions.</li>
 * </ol>
 *
 * <p>Verdict policy: a signature hit of {@link Severity#MEDIUM} or above is
 * {@link Verdict#MALICIOUS}; any other hit, or a heuristic alone, is
 * {@link Verdict#SUSPICIOUS}.
 */
public final class FileScanner {

    private final SignatureDatabase signatures;
    private final ScannerConfig config;
    private final Map<String, Pattern> regexCache;

    public FileScanner() {
        this(SignatureDatabase.builtin(), ScannerConfig.defaults());
    }

    public FileScanner(SignatureDatabase signatures, ScannerConfig config) {
        this.signatures = signatures;
        this.config = config;
        this.regexCache = new HashMap<>();
        for (ThreatSignature signature : signatures.byType(Type.REGEX)) {
            regexCache.put(signature.id(),
                    Pattern.compile(signature.pattern(), Pattern.CASE_INSENSITIVE | Pattern.DOTALL));
        }
    }

    public ScanResult scan(Path file) {
        long start = System.nanoTime();
        try {
            if (file == null) {
                return ScanResult.error(null, "no file supplied", elapsed(start));
            }
            if (!Files.isRegularFile(file)) {
                return ScanResult.error(file, "not a regular file", elapsed(start));
            }

            long size = Files.size(file);
            String sha256 = Hashing.sha256Hex(file);
            byte[] head = readHead(file);
            double entropy = EntropyAnalyzer.shannon(head);

            String content = new String(head, StandardCharsets.ISO_8859_1);
            String lowered = content.toLowerCase(Locale.ROOT);

            List<Threat> threats = matchSignatures(sha256, content, lowered);
            List<String> notes = heuristics(file, head, size, entropy);

            Verdict verdict = decide(threats, notes);
            String detail = notes.isEmpty()
                    ? threats.stream().map(Threat::name).reduce((a, b) -> a + ", " + b).orElse("")
                    : String.join("; ", notes);

            return new ScanResult(file, verdict, sha256, entropy, size, threats, elapsed(start), detail);
        } catch (IOException e) {
            String message = e.getMessage() == null ? e.toString() : e.getMessage();
            return ScanResult.error(file, message, elapsed(start));
        }
    }

    private List<Threat> matchSignatures(String sha256, String content, String lowered) {
        List<Threat> threats = new ArrayList<>();
        for (ThreatSignature signature : signatures.all()) {
            switch (signature.type()) {
                case HASH_SHA256 -> {
                    if (signature.pattern().equalsIgnoreCase(sha256)) {
                        threats.add(signature.toThreat("sha256=" + Hashing.abbreviate(sha256, 16)));
                    }
                }
                case CONTENT_STRING -> {
                    int index = lowered.indexOf(signature.pattern().toLowerCase(Locale.ROOT));
                    if (index >= 0) {
                        threats.add(signature.toThreat(evidence(content, index, signature.pattern().length())));
                    }
                }
                case REGEX -> {
                    Matcher matcher = regexCache.get(signature.id()).matcher(content);
                    if (matcher.find()) {
                        threats.add(signature.toThreat(evidence(content, matcher.start(), matcher.end() - matcher.start())));
                    }
                }
            }
        }
        return threats;
    }

    private List<String> heuristics(Path file, byte[] head, long size, double entropy) {
        List<String> notes = new ArrayList<>();
        String name = file.getFileName() == null ? "" : file.getFileName().toString().toLowerCase(Locale.ROOT);
        String extension = extensionOf(name);

        if (config.executableExtensions().contains(extension)) {
            int lastDot = name.lastIndexOf('.');
            int previousDot = lastDot > 0 ? name.lastIndexOf('.', lastDot - 1) : -1;
            if (previousDot > 0) {
                String decoy = name.substring(previousDot + 1, lastDot);
                if (config.decoyExtensions().contains(decoy)) {
                    notes.add("double extension '." + decoy + "." + extension + "' masquerading as a document");
                }
            }
        }

        if (head.length >= 2 && head[0] == 'M' && head[1] == 'Z'
                && !config.executableExtensions().contains(extension)) {
            notes.add("PE executable header inside a '." + extension + "' file");
        }

        if (entropy >= config.entropyThreshold() && size >= config.entropyMinBytes()) {
            notes.add(String.format(Locale.ROOT,
                    "high entropy %.2f bits/byte suggests packing or encryption", entropy));
        }
        return notes;
    }

    private static Verdict decide(List<Threat> threats, List<String> notes) {
        Severity worst = threats.stream()
                .map(Threat::severity)
                .max((a, b) -> Integer.compare(a.rank(), b.rank()))
                .orElse(null);
        if (worst != null && worst.atLeast(Severity.MEDIUM)) {
            return Verdict.MALICIOUS;
        }
        if (!threats.isEmpty() || !notes.isEmpty()) {
            return Verdict.SUSPICIOUS;
        }
        return Verdict.CLEAN;
    }

    private byte[] readHead(Path file) throws IOException {
        try (InputStream in = Files.newInputStream(file)) {
            return in.readNBytes(config.maxScanBytes());
        }
    }

    private static String evidence(String content, int index, int length) {
        int start = Math.max(0, index - 12);
        int end = Math.min(content.length(), index + Math.max(length, 1) + 12);
        String snippet = content.substring(start, end).replaceAll("\\p{Cntrl}", ".");
        return "..." + snippet.trim() + "...";
    }

    private static String extensionOf(String fileName) {
        int dot = fileName.lastIndexOf('.');
        if (dot < 0 || dot == fileName.length() - 1) {
            return "";
        }
        return fileName.substring(dot + 1);
    }

    private static long elapsed(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000L;
    }

    public SignatureDatabase signatures() {
        return signatures;
    }

    public ScannerConfig config() {
        return config;
    }
}
