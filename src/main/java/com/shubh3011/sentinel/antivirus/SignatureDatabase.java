package com.shubh3011.sentinel.antivirus;

import com.shubh3011.sentinel.model.Severity;
import com.shubh3011.sentinel.model.ThreatSignature;
import com.shubh3011.sentinel.model.ThreatSignature.Type;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * A set of {@link ThreatSignature} rules.
 *
 * <p>Rules are data, not code: the shipped database is a plain text resource and
 * users can layer their own file on top with {@link #load(Path)}. Fields are
 * tab-separated, which keeps regular expressions (and their {@code |}
 * alternation) unambiguous:
 *
 * <pre>id [TAB] name [TAB] severity [TAB] type [TAB] pattern [TAB] description</pre>
 *
 * Blank lines and lines starting with {@code #} are ignored.
 */
public final class SignatureDatabase {

    private static final String BUILTIN_RESOURCE = "/antivirus/signatures.db";

    private final List<ThreatSignature> signatures;

    public SignatureDatabase(List<ThreatSignature> signatures) {
        this.signatures = List.copyOf(signatures);
    }

    public static SignatureDatabase empty() {
        return new SignatureDatabase(List.of());
    }

    /** The bundled rule set shipped on the classpath. */
    public static SignatureDatabase builtin() {
        try (InputStream in = SignatureDatabase.class.getResourceAsStream(BUILTIN_RESOURCE)) {
            if (in == null) {
                throw new IOException("missing classpath resource " + BUILTIN_RESOURCE);
            }
            return new SignatureDatabase(parse(in));
        } catch (IOException e) {
            throw new IllegalStateException("could not load the built-in signature database", e);
        }
    }

    public static SignatureDatabase load(Path file) throws IOException {
        try (InputStream in = Files.newInputStream(file)) {
            return new SignatureDatabase(parse(in));
        }
    }

    static List<ThreatSignature> parse(InputStream in) throws IOException {
        List<ThreatSignature> parsed = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                parsed.add(parseLine(trimmed, lineNumber));
            }
        }
        return parsed;
    }

    private static ThreatSignature parseLine(String line, int lineNumber) {
        String[] parts = line.split("\t", 6);
        if (parts.length < 5) {
            throw new IllegalArgumentException(
                    "signature line " + lineNumber + " needs 5 tab-separated fields: " + line);
        }
        return new ThreatSignature(
                parts[0].trim(),
                parts[1].trim(),
                Severity.valueOf(parts[2].trim().toUpperCase()),
                Type.valueOf(parts[3].trim().toUpperCase()),
                parts[4].trim(),
                parts.length > 5 ? parts[5].trim() : "");
    }

    /** Returns a new database containing these rules plus {@code extra}. */
    public SignatureDatabase with(ThreatSignature... extra) {
        List<ThreatSignature> merged = new ArrayList<>(signatures);
        for (ThreatSignature signature : extra) {
            merged.add(Objects.requireNonNull(signature, "signature"));
        }
        return new SignatureDatabase(merged);
    }

    public List<ThreatSignature> all() {
        return signatures;
    }

    public List<ThreatSignature> byType(Type type) {
        return signatures.stream().filter(s -> s.type() == type).toList();
    }

    public int size() {
        return signatures.size();
    }
}
