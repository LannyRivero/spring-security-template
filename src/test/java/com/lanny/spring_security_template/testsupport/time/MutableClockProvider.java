package com.lanny.spring_security_template.testsupport.time;

import com.lanny.spring_security_template.domain.time.ClockProvider;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

/**
 * Mutable clock for advanced time-based testing.
 *
 * Allows advancing the time manually without waiting in real time.
 *
 * Typical use cases:
 * - Refresh token TTL tests
 * - Access token expiration tests
 * - Rate limiting window tests
 * - Key rotation scenarios
 */
public class MutableClockProvider implements ClockProvider {

    private Instant current;

    public MutableClockProvider(Instant start) {
        this.current = start;
    }

    /**
     * Moves the internal clock forward by the given number of seconds.
     */
    public void advanceSeconds(long seconds) {
        this.current = this.current.plusSeconds(seconds);
    }

    /**
     * Moves the internal clock forward by the given number of minutes.
     */
    public void advanceMinutes(long minutes) {
        advanceSeconds(minutes * 60);
    }

    @Override
    public Clock clock() {
        return Clock.fixed(current, ZoneOffset.UTC);
    }
}
