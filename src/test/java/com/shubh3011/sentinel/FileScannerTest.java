package com.shubh3011.sentinel;

import com.shubh3011.sentinel.antivirus.FileScanner;
import com.shubh3011.sentinel.model.ScanResult;
import com.shubh3011.sentinel.model.Verdict;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileScannerTest {

    @TempDir
    Path tempDir;

    @Test
    void detectsEicar() throws IOException {
        Path file = tempDir.resolve("eicar.com");
        Files.writeString(file, "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
                StandardCharsets.US_ASCII);
        ScanResult result = new FileScanner().scan(file);
        assertEquals(Verdict.MALICIOUS, result.verdict());
        assertTrue(result.threats().stream().anyMatch(t -> t.name().contains("EICAR")));
    }

    @Test
    void cleanFileIsClean() throws IOException {
        Path file = tempDir.resolve("notes.txt");
        Files.writeString(file, "Quarterly planning notes.\nEverything here is benign.\n");
        ScanResult result = new FileScanner().scan(file);
        assertEquals(Verdict.CLEAN, result.verdict());
        assertTrue(result.threats().isEmpty());
    }

    @Test
    void highEntropyFileIsSuspicious() throws IOException {
        byte[] data = new byte[4096];
        new java.util.Random(7).nextBytes(data);
        Path file = tempDir.resolve("payload.bin");
        Files.write(file, data);
        ScanResult result = new FileScanner().scan(file);
        assertEquals(Verdict.SUSPICIOUS, result.verdict());
        assertTrue(result.detail().contains("entropy"));
    }

    @Test
    void doubleExtensionIsSuspicious() throws IOException {
        Path file = tempDir.resolve("invoice.pdf.exe");
        Files.writeString(file, "not a pdf");
        ScanResult result = new FileScanner().scan(file);
        assertEquals(Verdict.SUSPICIOUS, result.verdict());
        assertTrue(result.detail().contains("double extension"));
    }

    @Test
    void missingFileIsError() {
        ScanResult result = new FileScanner().scan(tempDir.resolve("nope.txt"));
        assertEquals(Verdict.ERROR, result.verdict());
    }
}
