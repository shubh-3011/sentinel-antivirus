package com.shubh3011.sentinel.model;

/** Overall file-scan verdict produced by the antivirus engine. */
public enum Verdict {
    CLEAN,
    SUSPICIOUS,
    MALICIOUS,
    ERROR;

    public boolean isThreat() {
        return this == SUSPICIOUS || this == MALICIOUS;
    }
}
