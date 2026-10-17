package com.shubh3011.sentinel.model;

import java.time.Instant;

/** Persisted history entry for a completed scan. */
public record ScanRecord(
        long id,
        String filePath,
        String sha256,
        Verdict verdict,
        String threatSummary,
        double entropy,
        long sizeBytes,
        Instant scannedAt) {

    public static ScanRecord of(ScanResult result, Instant scannedAt) {
        return new ScanRecord(
                0L,
                result.file().toAbsolutePath().toString(),
                result.sha256(),
                result.verdict(),
                result.threatNames(),
                result.entropy(),
                result.sizeBytes(),
                scannedAt);
    }

    public ScanRecord withId(long newId) {
        return new ScanRecord(newId, filePath, sha256, verdict, threatSummary, entropy, sizeBytes, scannedAt);
    }
}
