package com.shubh3011.sentinel.model;

import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Outcome of scanning a single file.
 *
 * @param file           the scanned path
 * @param verdict        overall verdict
 * @param sha256         SHA-256 digest of the file, or {@code ""} when unreadable
 * @param entropy        Shannon entropy per byte, {@code 0.0} when unreadable
 * @param sizeBytes      file size, or {@code -1} when unreadable
 * @param threats        detections, ordered as they were discovered
 * @param durationMillis time spent scanning
 * @param detail         extra context, e.g. the heuristic that fired or an error message
 */
public record ScanResult(
        Path file,
        Verdict verdict,
        String sha256,
        double entropy,
        long sizeBytes,
        List<Threat> threats,
        long durationMillis,
        String detail) {

    public ScanResult {
        threats = threats == null ? List.of() : List.copyOf(threats);
    }

    public static ScanResult error(Path file, String message, long durationMillis) {
        return new ScanResult(file, Verdict.ERROR, "", 0.0, -1L, List.of(), durationMillis, message);
    }

    public boolean isClean() {
        return verdict == Verdict.CLEAN;
    }

    public boolean isMalicious() {
        return verdict == Verdict.MALICIOUS;
    }

    public Severity worstSeverity() {
        return threats.stream()
                .map(Threat::severity)
                .max((a, b) -> Integer.compare(a.rank(), b.rank()))
                .orElse(Severity.LOW);
    }

    public String threatNames() {
        return threats.stream().map(Threat::name).distinct().collect(Collectors.joining(", "));
    }

    public String fileName() {
        Path name = file.getFileName();
        return name == null ? file.toString() : name.toString();
    }
}
