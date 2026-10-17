package com.shubh3011.sentinel;

import com.shubh3011.sentinel.app.AppConfig;
import com.shubh3011.sentinel.app.AppContext;
import com.shubh3011.sentinel.app.DemoRunner;
import com.shubh3011.sentinel.model.Verdict;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DemoRunnerTest {

    @TempDir
    Path tempDir;

    @Test
    void runsEndToEnd() throws Exception {
        AppConfig config = AppConfig.of(tempDir.resolve(".data"));
        try (AppContext context = AppContext.open(config)) {
            DemoRunner.Outcome outcome = DemoRunner.run(context, tempDir.resolve("demo"));
            assertEquals(5, outcome.scans().size());
            assertTrue(outcome.maliciousCount() >= 1, "expected at least one malicious file");
            assertTrue(outcome.suspiciousCount() >= 2, "expected packed + disguised files to be suspicious");
            assertTrue(outcome.quarantined().isPresent());
            assertTrue(Files.exists(outcome.workspace()));
            assertTrue(context.historyRepository().count() == 5);
        }
    }
}
