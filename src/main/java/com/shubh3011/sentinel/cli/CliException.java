package com.shubh3011.sentinel.cli;

/** Signals a user-facing command error; the CLI turns it into a message and exit code 1. */
public class CliException extends RuntimeException {

    public CliException(String message) {
        super(message);
    }

    public CliException(String message, Throwable cause) {
        super(message, cause);
    }
}
