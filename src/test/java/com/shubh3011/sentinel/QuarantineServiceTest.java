package com.shubh3011.sentinel;

import com.shubh3011.sentinel.antivirus.QuarantineService;
import com.shubh3011.sentinel.antivirus.FileScanner;
import com.shubh3011.sentinel.model.ScanResult;
import com.shubh3011.sentinel.util.TimeProvider;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class QuarantineServiceTest {

    @TempDir
    Path tempDir;

    @Test
    void quarantinesAndRestoresFile() throws Exception {
        Path source = tempDir.resolve("threat.bin");
        Files.writeString(source, "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
        ScanResult result = new FileScanner().scan(source);

        Path quarantineDir = tempDir.resolve("quarantine");
        QuarantineService service = new QuarantineService(quarantineDir, TimeProvider.system());
        var record = service.quarantine(source, result);

        assertTrue(!Files.exists(source));
        assertTrue(Files.isRegularFile(record.quarantinedPath()));
        assertEquals(1, service.size());

        Path restored = service.restore(record.id());
        assertTrue(Files.isRegularFile(restored));
        assertEquals(source.toAbsolutePath(), restored.toAbsolutePath());
        assertEquals(0, service.size());
    }
}
