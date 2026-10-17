package com.shubh3011.sentinel.db;

import com.shubh3011.sentinel.model.ScanRecord;
import com.shubh3011.sentinel.model.Verdict;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

/** Append-only history of antivirus scans. */
public final class ScanHistoryRepository {

    private static final String COLUMNS =
            "id, file_path, sha256, verdict, threat_summary, entropy, size_bytes, scanned_at";

    private final Database database;

    public ScanHistoryRepository(Database database) {
        this.database = database;
    }

    public ScanRecord save(ScanRecord record) {
        long id = database.insert(
                """
                INSERT INTO scan_record(file_path, sha256, verdict, threat_summary, entropy, size_bytes, scanned_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                ps -> {
                    ps.setString(1, record.filePath());
                    ps.setString(2, record.sha256());
                    ps.setString(3, record.verdict().name());
                    ps.setString(4, record.threatSummary());
                    ps.setDouble(5, record.entropy());
                    ps.setLong(6, record.sizeBytes());
                    ps.setString(7, Database.toText(record.scannedAt()));
                });
        return record.withId(id);
    }

    public List<ScanRecord> recent(int limit) {
        return database.query("SELECT " + COLUMNS + " FROM scan_record ORDER BY scanned_at DESC LIMIT ?",
                ps -> ps.setInt(1, limit), ScanHistoryRepository::map);
    }

    public int countByVerdict(Verdict verdict) {
        return database.query("SELECT COUNT(*) AS c FROM scan_record WHERE verdict = ?",
                ps -> ps.setString(1, verdict.name()), rs -> rs.getInt("c")).get(0);
    }

    public int count() {
        return database.query("SELECT COUNT(*) AS c FROM scan_record", Database.NO_PARAMETERS, rs -> rs.getInt("c"))
                .get(0);
    }

    private static ScanRecord map(ResultSet rs) throws SQLException {
        return new ScanRecord(
                rs.getLong("id"),
                rs.getString("file_path"),
                rs.getString("sha256"),
                Verdict.valueOf(rs.getString("verdict")),
                rs.getString("threat_summary"),
                rs.getDouble("entropy"),
                rs.getLong("size_bytes"),
                Database.toInstant(rs.getString("scanned_at")));
    }
}
