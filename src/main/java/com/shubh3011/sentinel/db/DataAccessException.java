package com.shubh3011.sentinel.db;

/** Unchecked wrapper for JDBC failures, keeping the rest of the code SQLException-free. */
public class DataAccessException extends RuntimeException {

    public DataAccessException(String message, Throwable cause) {
        super(message, cause);
    }

    public DataAccessException(String message) {
        super(message);
    }
}
