package com.shubh3011.sentinel.db;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Thin, dependency-light SQLite facade.
 *
 * <p>The suite is a single-user desktop application, so one shared connection is
 * enough and removes an entire class of connection-pooling bugs. Every accessor is
 * {@code synchronized} on the instance, which serialises access across the JavaFX
 * thread and any worker threads. JDBC boilerplate lives here so repositories stay
 * declarative.
 */
public final class Database implements AutoCloseable {

    /** Binds parameters on a {@link PreparedStatement}. */
    @FunctionalInterface
    public interface StatementBinder {
        void bind(PreparedStatement statement) throws SQLException;
    }

    /** Maps the current row of a {@link ResultSet}. */
    @FunctionalInterface
    public interface RowMapper<T> {
        T map(ResultSet resultSet) throws SQLException;
    }

    /** A binder that sets nothing, for statements without parameters. */
    public static final StatementBinder NO_PARAMETERS = statement -> {
    };

    private final Connection connection;
    private final Path file;
    private boolean closed;

    private Database(Connection connection, Path file) {
        this.connection = connection;
        this.file = file;
    }

    /** Opens (creating if needed) a file-backed database and applies the schema. */
    public static Database open(Path file) {
        Path absolute = file.toAbsolutePath();
        try {
            Path parent = absolute.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Connection connection = DriverManager.getConnection("jdbc:sqlite:" + absolute);
            configure(connection, true);
            Database database = new Database(connection, absolute);
            SchemaInitializer.initialize(database);
            return database;
        } catch (IOException | SQLException e) {
            throw new DataAccessException("could not open database at " + absolute, e);
        }
    }

    /** Ephemeral database kept entirely in memory; used by the tests. */
    public static Database inMemory() {
        try {
            Connection connection = DriverManager.getConnection("jdbc:sqlite::memory:");
            configure(connection, false);
            Database database = new Database(connection, null);
            SchemaInitializer.initialize(database);
            return database;
        } catch (SQLException e) {
            throw new DataAccessException("could not open in-memory database", e);
        }
    }

    private static void configure(Connection connection, boolean fileBacked) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA foreign_keys = ON");
            if (fileBacked) {
                statement.execute("PRAGMA journal_mode = WAL");
            }
            statement.execute("PRAGMA busy_timeout = 5000");
        }
    }

    public synchronized <T> List<T> query(String sql, StatementBinder binder, RowMapper<T> mapper) {
        ensureOpen();
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            binder.bind(statement);
            try (ResultSet resultSet = statement.executeQuery()) {
                List<T> rows = new ArrayList<>();
                while (resultSet.next()) {
                    rows.add(mapper.map(resultSet));
                }
                return rows;
            }
        } catch (SQLException e) {
            throw new DataAccessException("query failed: " + sql, e);
        }
    }

    public synchronized int update(String sql, StatementBinder binder) {
        ensureOpen();
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            binder.bind(statement);
            return statement.executeUpdate();
        } catch (SQLException e) {
            throw new DataAccessException("update failed: " + sql, e);
        }
    }

    /** Executes an insert and returns the generated key, or {@code 0} if none. */
    public synchronized long insert(String sql, StatementBinder binder) {
        ensureOpen();
        try (PreparedStatement statement = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            binder.bind(statement);
            statement.executeUpdate();
            try (ResultSet keys = statement.getGeneratedKeys()) {
                return keys.next() ? keys.getLong(1) : 0L;
            }
        } catch (SQLException e) {
            throw new DataAccessException("insert failed: " + sql, e);
        }
    }

    public synchronized void execute(String sql) {
        ensureOpen();
        try (Statement statement = connection.createStatement()) {
            statement.execute(sql);
        } catch (SQLException e) {
            throw new DataAccessException("statement failed: " + sql, e);
        }
    }

    public Path file() {
        return file;
    }

    public synchronized boolean isClosed() {
        return closed;
    }

    private void ensureOpen() {
        if (closed) {
            throw new DataAccessException("database is closed");
        }
    }

    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            connection.close();
        } catch (SQLException e) {
            throw new DataAccessException("could not close database", e);
        }
    }

    /** Shared {@code Instant <-> ISO-8601 TEXT} convention. */
    static String toText(Instant instant) {
        return instant.toString();
    }

    static Instant toInstant(String text) {
        return Instant.parse(text);
    }
}
