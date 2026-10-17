package com.shubh3011.sentinel;

import com.shubh3011.sentinel.antivirus.EntropyAnalyzer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EntropyAnalyzerTest {

    @Test
    void emptyDataHasZeroEntropy() {
        assertEquals(0.0, EntropyAnalyzer.shannon(new byte[0]), 1e-9);
    }

    @Test
    void constantDataHasZeroEntropy() {
        byte[] data = new byte[1000];
        assertEquals(0.0, EntropyAnalyzer.shannon(data), 1e-9);
    }

    @Test
    void randomDataApproachesEight() {
        byte[] data = new byte[65536];
        new java.util.Random(1).nextBytes(data);
        assertTrue(EntropyAnalyzer.shannon(data) > 7.9);
    }

    @Test
    void uniformDistributionIsMaximal() {
        byte[] data = new byte[256 * 100];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i % 256);
        }
        assertEquals(8.0, EntropyAnalyzer.shannon(data), 1e-9);
    }
}
