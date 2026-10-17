package com.shubh3011.sentinel.app;

import com.shubh3011.sentinel.antivirus.FileScanner;
import com.shubh3011.sentinel.antivirus.QuarantineService;
import com.shubh3011.sentinel.antivirus.ScannerConfig;
import com.shubh3011.sentinel.antivirus.SignatureDatabase;
import com.shubh3011.sentinel.db.Database;
import com.shubh3011.sentinel.db.ScanHistoryRepository;
import com.shubh3011.sentinel.model.ScanRecord;
import com.shubh3011.sentinel.model.ScanResult;
import com.shubh3011.sentinel.util.TimeProvider;

/**
 * Composition root for Sentinel. Builds the scanner, history store and quarantine
 * once and shares them with the CLI and the JavaFX UI.
 */
public final class AppContext implements AutoCloseable {

    private final AppConfig config;
    private final Database database;
    private final ScanHistoryRepository historyRepository;
    private final FileScanner fileScanner;
    private final QuarantineService quarantineService;
    private final TimeProvider clock;

    private AppContext(
            AppConfig config,
            Database database,
            ScanHistoryRepository historyRepository,
            FileScanner fileScanner,
            QuarantineService quarantineService,
            TimeProvider clock) {
        this.config = config;
        this.database = database;
        this.historyRepository = historyRepository;
        this.fileScanner = fileScanner;
        this.quarantineService = quarantineService;
        this.clock = clock;
    }

    public static AppContext open(AppConfig config) {
        return open(config, TimeProvider.system());
    }

    public static AppContext open(AppConfig config, TimeProvider clock) {
        Database database = Database.open(config.databaseFile());
        ScanHistoryRepository history = new ScanHistoryRepository(database);
        FileScanner scanner = new FileScanner(SignatureDatabase.builtin(), ScannerConfig.defaults());
        QuarantineService quarantine = new QuarantineService(config.quarantineDir(), clock);
        return new AppContext(config, database, history, scanner, quarantine, clock);
    }

    /** A scanner using a caller-supplied signature set. */
    public FileScanner scannerWith(SignatureDatabase signatures) {
        return new FileScanner(signatures, fileScanner.config());
    }

    public ScanRecord recordScan(ScanResult result) {
        return historyRepository.save(ScanRecord.of(result, clock.now()));
    }

    public AppConfig config() {
        return config;
    }

    public Database database() {
        return database;
    }

    public ScanHistoryRepository historyRepository() {
        return historyRepository;
    }

    public FileScanner fileScanner() {
        return fileScanner;
    }

    public QuarantineService quarantineService() {
        return quarantineService;
    }

    public TimeProvider clock() {
        return clock;
    }

    @Override
    public void close() {
        database.close();
    }
}
