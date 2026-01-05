package com.lanny.spring_security_template.infrastructure.adapter.security;

import java.time.Duration;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenConsumptionPort;

/**
 * ============================================================
 * NoOpRefreshTokenConsumptionAdapter
 * ============================================================
 *
 * No-Op implementation of {@link RefreshTokenConsumptionPort}.
 *
 * <p>
 * This adapter allows refresh tokens to be reused without restriction
 * and MUST ONLY be used in non-production environments.
 * </p>
 *
 * <h2>Intended usage</h2>
 * <ul>
 * <li>Unit tests</li>
 * <li>Local development</li>
 * <li>Environments without Redis</li>
 * </ul>
 *
 * <h2>Security warning</h2>
 * <p>
 * This implementation provides NO protection against refresh token
 * replay attacks and MUST NEVER be enabled in production.
 * </p>
 *
 * <h2>Profiles</h2>
 * <ul>
 * <li><b>test</b></li>
 * <li><b>local</b></li>
 * </ul>
 */
@Component
@Profile({ "test", "local" })
public class NoOpRefreshTokenConsumptionAdapter
        implements RefreshTokenConsumptionPort {

    /**
     * Always returns {@code true}, allowing unlimited refresh token reuse.
     *
     * @param jti          refresh token identifier
     * @param remainingTtl remaining lifetime of the token
     * @return always {@code true}
     */
    @Override
    public boolean consume(String jti, Duration remainingTtl) {
        return true;
    }
}
