package com.lanny.spring_security_template.domain.time;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Abstraction for accessing the current time in a uniform way.
 *
 * All components in the system MUST obtain time exclusively from this
 * interface.
 * Never call Instant.now() directly.
 */
public interface ClockProvider {

    /** Returns the current application clock (usually UTC). */
    Clock clock();

    /** Convenience: get the current instant. */
    default Instant now() {
        return Instant.now(clock());
    }

    /** Convenience: now plus given seconds. */
    default Instant plusSeconds(long seconds) {
        return now().plusSeconds(seconds);
    }

    /** Convenience: now minus given seconds. */
    default Instant minusSeconds(long seconds) {
        return now().minusSeconds(seconds);
    }

    /** Convenience: truncate to seconds (useful for tokens). */
    default Instant nowTruncatedToSeconds() {
        return now().truncatedTo(ChronoUnit.SECONDS);
    }
}
