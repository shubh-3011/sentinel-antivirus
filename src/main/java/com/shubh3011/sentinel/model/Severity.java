package com.shubh3011.sentinel.model;

/** Threat severity, ordered from least to most dangerous. */
public enum Severity {
    LOW(1),
    MEDIUM(2),
    HIGH(3),
    CRITICAL(4);

    private final int rank;

    Severity(int rank) {
        this.rank = rank;
    }

    public int rank() {
        return rank;
    }

    public boolean atLeast(Severity other) {
        return rank >= other.rank;
    }
}
