package com.lanny.spring_security_template.infrastructure.time;

import java.time.Clock;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.domain.time.ClockProvider;

/**
 * ============================================================
 * SystemClockProvider
 * ============================================================
 *
 * <p>
 * Production-grade {@link ClockProvider} implementation backed by the
 * system UTC clock.
 * </p>
 *
 * <h2>Purpose</h2>
 * <p>
 * Provides the current system time in UTC for all security-sensitive
 * operations such as:
 * </p>
 * <ul>
 * <li>JWT issuance and expiration</li>
 * <li>Refresh token TTL validation</li>
 * <li>Auditing and timestamp generation</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Uses {@link Clock#systemUTC()} to avoid timezone-related issues</li>
 * <li>Implements {@link ClockProvider} defined in the domain layer</li>
 * <li>Enabled only for {@code dev} and {@code prod} profiles</li>
 * </ul>
 *
 * <p>
 * For deterministic testing scenarios, see {@link FixedClockProvider}.
 * </p>
 */

@Component
@Profile({ "dev", "prod" })
public class SystemClockProvider implements ClockProvider {

    private final Clock clock = Clock.systemUTC();

    @Override
    public Clock clock() {
        return clock;
    }
}
