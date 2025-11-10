package com.lanny.spring_security_template.shared;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import org.springframework.stereotype.Component;


/**
 * Provides a centralized source of time for the application.
 * Useful for deterministic tests and future policies like key rotation or token
 * TTLs.
 */
@Component
public class ClockProvider {

    private final Clock clock;

    public ClockProvider() {
        this(Clock.systemUTC());
    }

    public ClockProvider(Clock clock) {
        this.clock = clock;
    }

    public Instant now() {
        return Instant.now(clock);
    }

    public ZoneId zone() {
        return clock.getZone();
    }
}
