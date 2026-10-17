package com.shubh3011.sentinel.db;

/** Idempotent schema creation for the antivirus domain. */
final class SchemaInitializer {

    private static final int SCHEMA_VERSION = 1;

    private static final String[] STATEMENTS = {
        """
        CREATE TABLE IF NOT EXISTS scan_record (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path      TEXT NOT NULL,
            sha256         TEXT NOT NULL,
            verdict        TEXT NOT NULL,
            threat_summary TEXT NOT NULL,
            entropy        REAL NOT NULL,
            size_bytes     INTEGER NOT NULL,
            scanned_at     TEXT NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_scan_verdict ON scan_record(verdict)",
        "CREATE INDEX IF NOT EXISTS idx_scan_time ON scan_record(scanned_at)",
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL
        )
        """,
    };

    private SchemaInitializer() {
    }

    static void initialize(Database database) {
        for (String statement : STATEMENTS) {
            database.execute(statement);
        }
        int existing = database.query("SELECT COUNT(*) AS c FROM schema_version", Database.NO_PARAMETERS,
                rs -> rs.getInt("c")).get(0);
        if (existing == 0) {
            database.update("INSERT INTO schema_version(version) VALUES (?)", ps -> ps.setInt(1, SCHEMA_VERSION));
        }
    }
}
