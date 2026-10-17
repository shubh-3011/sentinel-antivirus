package com.shubh3011.sentinel;

import com.shubh3011.sentinel.antivirus.FileScanner;
import com.shubh3011.sentinel.antivirus.ScannerConfig;
import com.shubh3011.sentinel.antivirus.SignatureDatabase;
import com.shubh3011.sentinel.model.Severity;
import com.shubh3011.sentinel.model.ScanResult;
import com.shubh3011.sentinel.model.ThreatSignature;
import com.shubh3011.sentinel.model.Verdict;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureDatabaseTest {

    @TempDir
    Path tempDir;

    @Test
    void builtinDatabaseLoads() {
        SignatureDatabase database = SignatureDatabase.builtin();
        assertTrue(database.size() >= 10);
        assertTrue(database.byType(ThreatSignature.Type.HASH_SHA256).stream()
                .anyMatch(s -> s.name().contains("EICAR")));
    }

    @Test
    void regexAlternationSurvivesTabDelimitedParsing() throws IOException {
        Path file = tempDir.resolve("custom.db");
        Files.writeString(file,
                "animal-exe\tAnimal Executable\tHIGH\tREGEX\t(cat|dog)\\.exe\tMatches cat.exe or dog.exe\n",
                StandardCharsets.UTF_8);
        SignatureDatabase database = SignatureDatabase.load(file);
        assertEquals(1, database.size());
        assertTrue(database.all().get(0).pattern().contains("|"));

        Path sample = tempDir.resolve("sample.txt");
        Files.writeString(sample, "please run dog.exe now");

        FileScanner scanner = new FileScanner(database, ScannerConfig.defaults());
        ScanResult result = scanner.scan(sample);
        assertEquals(Verdict.MALICIOUS, result.verdict());
        assertEquals(Severity.HIGH, result.worstSeverity());
    }

    @Test
    void malformedLineIsRejected() throws IOException {
        Path file = tempDir.resolve("broken.db");
        Files.writeString(file, "only|three|fields\n", StandardCharsets.UTF_8);
        boolean threw = false;
        try {
            SignatureDatabase.load(file);
        } catch (IllegalArgumentException e) {
            threw = true;
        }
        assertTrue(threw, "expected a malformed signature line to be rejected");
    }

    @Test
    void commentsAndBlankLinesAreIgnored() throws IOException {
        Path file = tempDir.resolve("comments.db");
        Files.writeString(file, "# a comment\n\n\t\t\t\t\t\n", StandardCharsets.UTF_8);
        SignatureDatabase database = SignatureDatabase.load(file);
        assertEquals(0, database.size());
    }
}
