package com.shubh3011.sentinel.util;

import java.time.Instant;

/**
 * Abstraction over "now" so that time-dependent logic (attendance status, report
 * windows) can be driven deterministically from tests instead of the wall clock.
 */
@FunctionalInterface
public interface TimeProvider {

    Instant now();

    /** Wall-clock implementation used in production. */
    static TimeProvider system() {
        return Instant::now;
    }

    /** Frozen clock, handy for tests. */
    static TimeProvider fixed(Instant instant) {
        return () -> instant;
    }
}
