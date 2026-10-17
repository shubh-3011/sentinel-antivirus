package com.shubh3011.sentinel.antivirus;

import java.util.Set;

/**
 * Tunables for {@link FileScanner}.
 *
 * @param entropyThreshold  entropy above which a sizeable file looks packed/encrypted
 * @param entropyMinBytes   ignore entropy for files smaller than this (avoids false positives)
 * @param maxScanBytes      how much of a file to load for content and entropy analysis
 * @param executableExtensions extensions treated as executable payloads
 * @param decoyExtensions   document/media extensions abused in double-extension tricks
 */
public record ScannerConfig(
        double entropyThreshold,
        long entropyMinBytes,
        int maxScanBytes,
        Set<String> executableExtensions,
        Set<String> decoyExtensions) {

    public ScannerConfig {
        if (entropyThreshold < 0.0 || entropyThreshold > EntropyAnalyzer.MAX_BITS_PER_BYTE) {
            throw new IllegalArgumentException("entropyThreshold must be within [0, 8]");
        }
        if (maxScanBytes <= 0) {
            throw new IllegalArgumentException("maxScanBytes must be positive");
        }
        executableExtensions = Set.copyOf(executableExtensions);
        decoyExtensions = Set.copyOf(decoyExtensions);
    }

    public static ScannerConfig defaults() {
        return new ScannerConfig(
                7.2,
                2048,
                16 * 1024 * 1024,
                Set.of("exe", "dll", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "js", "jar", "msi"),
                Set.of("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "mp3", "mp4"));
    }

    public ScannerConfig withEntropyThreshold(double value) {
        return new ScannerConfig(value, entropyMinBytes, maxScanBytes, executableExtensions, decoyExtensions);
    }
}
