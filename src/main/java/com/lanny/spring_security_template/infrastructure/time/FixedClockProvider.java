package com.lanny.spring_security_template.infrastructure.time;

import com.lanny.spring_security_template.domain.time.ClockProvider;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

/**
 * Fixed, deterministic clock for testing.
 */
public class FixedClockProvider implements ClockProvider {

    private final Clock fixed;

    public FixedClockProvider(Instant instant) {
        this.fixed = Clock.fixed(instant, ZoneOffset.UTC);
    }

    @Override
    public Clock clock() {
        return fixed;
    }
}

