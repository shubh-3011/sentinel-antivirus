package com.shubh3011.sentinel;

import com.shubh3011.sentinel.db.Database;
import com.shubh3011.sentinel.db.ScanHistoryRepository;
import com.shubh3011.sentinel.model.ScanRecord;
import com.shubh3011.sentinel.model.ScanResult;
import com.shubh3011.sentinel.model.Verdict;
import java.nio.file.Path;
import java.time.Instant;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RepositoryIntegrationTest {

    @Test
    void scanHistoryPersistsAndCounts() {
        Database database = Database.inMemory();
        ScanHistoryRepository repository = new ScanHistoryRepository(database);
        ScanResult result = new ScanResult(Path.of("x.txt"), Verdict.MALICIOUS, "abc", 4.2, 10,
                java.util.List.of(), 5, "test");
        ScanRecord record = repository.save(ScanRecord.of(result, Instant.parse("2026-01-01T00:00:00Z")));
        assertTrue(record.id() > 0);
        assertEquals(1, repository.count());
        assertEquals(1, repository.countByVerdict(Verdict.MALICIOUS));
        assertEquals(0, repository.countByVerdict(Verdict.CLEAN));
        assertEquals(1, repository.recent(10).size());
    }
}
