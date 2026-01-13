package com.lanny.spring_security_template.infrastructure.time;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import com.lanny.spring_security_template.domain.time.ClockProvider;

/**
 * ============================================================
 * FixedClockProvider
 * ============================================================
 *
 * <p>
 * Deterministic {@link ClockProvider} implementation backed by a fixed
 * {@link java.time.Instant}.
 * </p>
 *
 * <h2>Purpose</h2>
 * <p>
 * This implementation is intended for:
 * </p>
 * <ul>
 * <li>Unit tests</li>
 * <li>Integration tests</li>
 * <li>Deterministic simulations and time-dependent scenarios</li>
 * </ul>
 *
 * <h2>Non-production usage</h2>
 * <p>
 * This clock MUST NOT be used in production environments, as it freezes
 * time and breaks expiration, auditing and security guarantees.
 * </p>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Implements {@link ClockProvider} defined in the domain layer</li>
 * <li>Delegates to
 * {@link java.time.Clock#fixed(Instant, java.time.ZoneId)}</li>
 * <li>Thread-safe and immutable</li>
 * </ul>
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
