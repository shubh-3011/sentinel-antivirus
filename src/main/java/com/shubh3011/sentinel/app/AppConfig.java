package com.shubh3011.sentinel.app;

import java.nio.file.Path;

/**
 * Filesystem layout for Sentinel.
 *
 * @param dataDir       root directory for runtime state
 * @param databaseFile  SQLite database holding scan history
 * @param quarantineDir isolated store for detected threats
 */
public record AppConfig(Path dataDir, Path databaseFile, Path quarantineDir) {

    /** Environment variable that overrides the default data directory. */
    public static final String HOME_ENV = "SENTINEL_HOME";

    public AppConfig {
        if (dataDir == null || databaseFile == null || quarantineDir == null) {
            throw new IllegalArgumentException("all paths are required");
        }
    }

    public static AppConfig of(Path dataDir) {
        Path absolute = dataDir.toAbsolutePath().normalize();
        return new AppConfig(absolute, absolute.resolve("sentinel.db"), absolute.resolve("quarantine"));
    }

    /** {@code $SENTINEL_HOME}, else {@code ~/.sentinel-antivirus}. */
    public static AppConfig defaults() {
        String home = System.getenv(HOME_ENV);
        Path dir = home == null || home.isBlank()
                ? Path.of(System.getProperty("user.home"), ".sentinel-antivirus")
                : Path.of(home);
        return of(dir);
    }

    public AppConfig withDataDir(Path newDataDir) {
        return of(newDataDir);
    }
}
