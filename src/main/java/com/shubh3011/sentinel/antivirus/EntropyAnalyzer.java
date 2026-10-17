package com.shubh3011.sentinel.antivirus;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Shannon entropy per byte, used as a cheap "is this packed or encrypted?" signal.
 *
 * <p>Plain text, source code and structured documents sit well under 6 bits/byte,
 * while compressed or encrypted payloads approach 8.
 */
public final class EntropyAnalyzer {

    public static final double MAX_BITS_PER_BYTE = 8.0;

    private EntropyAnalyzer() {
    }

    public static double shannon(byte[] data) {
        if (data == null || data.length == 0) {
            return 0.0;
        }
        int[] frequencies = new int[256];
        for (byte b : data) {
            frequencies[b & 0xFF]++;
        }
        double entropy = 0.0;
        double total = data.length;
        for (int frequency : frequencies) {
            if (frequency == 0) {
                continue;
            }
            double probability = frequency / total;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        return entropy;
    }

    /** Entropy of the first {@code maxBytes} of a file. */
    public static double of(Path file, int maxBytes) throws IOException {
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buffer = in.readNBytes(maxBytes);
            return shannon(buffer);
        }
    }
}
