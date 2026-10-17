package com.shubh3011.sentinel;

import com.shubh3011.sentinel.util.Hashing;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HashingTest {

    @Test
    void knownSha256OfAbc() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                Hashing.sha256Hex("abc".getBytes()));
    }

    @Test
    void fileHashMatchesBytes(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("data.bin");
        byte[] data = "hello world".getBytes();
        Files.write(file, data);
        assertEquals(Hashing.sha256Hex(data), Hashing.sha256Hex(file));
    }

    @Test
    void abbreviateShortens() {
        assertEquals("ba7816bf8f...", Hashing.abbreviate("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 10));
    }
}
