package com.shubh3011.sentinel.antivirus;

import com.shubh3011.sentinel.model.ScanResult;
import com.shubh3011.sentinel.model.Verdict;
import com.shubh3011.sentinel.util.TimeProvider;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Moves detected threats out of harm's way into an isolated folder, preserving
 * enough metadata to audit or restore them later.
 *
 * <p>Each quarantined file is stored as {@code <id>.bin} next to a {@code <id>.meta}
 * sidecar. Nothing is ever deleted, which keeps the operation reversible.
 */
public final class QuarantineService {

    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneOffset.UTC);

    private final Path quarantineDir;
    private final TimeProvider clock;

    public QuarantineService(Path quarantineDir, TimeProvider clock) {
        this.quarantineDir = quarantineDir.toAbsolutePath();
        this.clock = clock;
    }

    /** Quarantines a file, returning the audit record. */
    public QuarantinedFile quarantine(Path source, ScanResult result) throws IOException {
        if (source == null || !Files.isRegularFile(source)) {
            throw new IOException("cannot quarantine, not a regular file: " + source);
        }
        Files.createDirectories(quarantineDir);
        String id = uniqueId(source);
        Path payload = quarantineDir.resolve(id + ".bin");
        move(source, payload);
        writeMetadata(quarantineDir.resolve(id + ".meta"), source.toAbsolutePath(), result);
        return new QuarantinedFile(id, source.toAbsolutePath(), payload, result.verdict(),
                result.threatNames(), clock.now());
    }

    /** Restores a previously quarantined file to its original location. */
    public Path restore(String id) throws IOException {
        Path payload = quarantineDir.resolve(id + ".bin");
        Path metadata = quarantineDir.resolve(id + ".meta");
        if (!Files.isRegularFile(payload) || !Files.isRegularFile(metadata)) {
            throw new IOException("unknown quarantine id: " + id);
        }
        Map<String, String> fields = readMetadata(metadata);
        Path original = Path.of(fields.getOrDefault("original", payload.toString()));
        if (original.getParent() != null) {
            Files.createDirectories(original.getParent());
        }
        move(payload, original);
        Files.deleteIfExists(metadata);
        return original;
    }

    public List<QuarantinedFile> list() throws IOException {
        if (!Files.isDirectory(quarantineDir)) {
            return List.of();
        }
        try (Stream<Path> entries = Files.list(quarantineDir)) {
            List<QuarantinedFile> records = new ArrayList<>();
            for (Path entry : entries.filter(p -> p.getFileName().toString().endsWith(".meta")).toList()) {
                records.add(read(entry));
            }
            records.sort(Comparator.comparing(QuarantinedFile::quarantinedAt).reversed());
            return records;
        }
    }

    public int size() throws IOException {
        return list().size();
    }

    private QuarantinedFile read(Path metadata) throws IOException {
        Map<String, String> fields = readMetadata(metadata);
        String id = metadata.getFileName().toString().replace(".meta", "");
        return new QuarantinedFile(
                id,
                Path.of(fields.getOrDefault("original", "")),
                quarantineDir.resolve(id + ".bin"),
                Verdict.valueOf(fields.getOrDefault("verdict", "SUSPICIOUS")),
                fields.getOrDefault("threats", ""),
                Instant.parse(fields.getOrDefault("quarantinedAt", clock.now().toString())));
    }

    private String uniqueId(Path source) {
        String fileName = source.getFileName() == null ? "file" : source.getFileName().toString();
        String sanitized = fileName.replaceAll("[^A-Za-z0-9._-]", "_");
        String base = STAMP.format(clock.now()) + "-" + sanitized;
        String candidate = base;
        int suffix = 2;
        while (Files.exists(quarantineDir.resolve(candidate + ".bin"))) {
            candidate = base + "-" + suffix++;
        }
        return candidate;
    }

    private static void move(Path from, Path to) throws IOException {
        try {
            Files.move(from, to, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException atomicFailed) {
            Files.copy(from, to, StandardCopyOption.REPLACE_EXISTING);
            Files.delete(from);
        }
    }

    private void writeMetadata(Path metadata, Path original, ScanResult result) throws IOException {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("original", original.toString());
        fields.put("verdict", result.verdict().name());
        fields.put("threats", result.threatNames());
        fields.put("detail", result.detail());
        fields.put("entropy", String.format(Locale.ROOT, "%.4f", result.entropy()));
        fields.put("sha256", result.sha256());
        fields.put("quarantinedAt", clock.now().toString());
        StringBuilder builder = new StringBuilder();
        fields.forEach((key, value) -> builder.append(key).append('=').append(value).append('\n'));
        Files.writeString(metadata, builder.toString(), StandardCharsets.UTF_8);
    }

    private static Map<String, String> readMetadata(Path metadata) throws IOException {
        Map<String, String> fields = new LinkedHashMap<>();
        for (String line : Files.readAllLines(metadata, StandardCharsets.UTF_8)) {
            int separator = line.indexOf('=');
            if (separator > 0) {
                fields.put(line.substring(0, separator), line.substring(separator + 1));
            }
        }
        return fields;
    }

    public Path directory() {
        return quarantineDir;
    }

    /**
     * Audit record for one quarantined artefact.
     *
     * @param id              quarantine identifier
     * @param originalPath    where the file came from
     * @param quarantinedPath where the payload now lives
     * @param verdict         verdict at quarantine time
     * @param threatSummary   comma-separated threat names
     * @param quarantinedAt   when it was quarantined
     */
    public record QuarantinedFile(
            String id,
            Path originalPath,
            Path quarantinedPath,
            Verdict verdict,
            String threatSummary,
            Instant quarantinedAt) {
    }
}
