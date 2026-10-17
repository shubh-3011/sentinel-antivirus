package com.shubh3011.sentinel;

import com.shubh3011.sentinel.cli.Main;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CliTest {

    private static final String EICAR =
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    private static int run(String... args) {
        PrintStream original = System.out;
        System.setOut(new PrintStream(OutputStream.nullOutputStream()));
        try {
            return new Main().execute(args);
        } finally {
            System.setOut(original);
        }
    }

    @Test
    void infoSucceeds(@TempDir Path tempDir) {
        int code = run("info", "--data-dir", tempDir.resolve("data").toString(), "--no-color");
        assertEquals(0, code);
    }

    @Test
    void scanReturnsOneForMalware(@TempDir Path tempDir) throws Exception {
        Path sample = tempDir.resolve("eicar.com");
        Files.writeString(sample, EICAR, StandardCharsets.US_ASCII);
        int code = run("scan", sample.toString(), "--data-dir", tempDir.resolve("data").toString(), "--no-color");
        assertEquals(1, code);
    }

    @Test
    void scanReturnsZeroForCleanFile(@TempDir Path tempDir) throws Exception {
        Path sample = tempDir.resolve("notes.txt");
        Files.writeString(sample, "nothing to see here\n");
        int code = run("scan", sample.toString(), "--data-dir", tempDir.resolve("data").toString(), "--no-color");
        assertEquals(0, code);
    }

    @Test
    void unknownCommandIsUsageError(@TempDir Path tempDir) {
        int code = run("nonsense", "--data-dir", tempDir.resolve("data").toString(), "--no-color");
        assertEquals(2, code);
    }
}
