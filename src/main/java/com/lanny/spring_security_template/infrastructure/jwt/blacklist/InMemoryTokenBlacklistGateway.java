package com.lanny.spring_security_template.infrastructure.jwt.blacklist;

import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.domain.time.ClockProvider;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory blacklist for revoked JWTs.
 *
 * <p>
 * Intended exclusively for <b>dev</b> and <b>test</b> profiles.
 * Stores revoked JWT IDs (jti) together with their expiration timestamp.
 * </p>
 *
 * <p>
 * <b>NOT FOR PRODUCTION</b> — production deployments must use a
 * distributed store such as Redis.
 * </p>
 */
@Component
@Profile({ "dev", "test" })
public class InMemoryTokenBlacklistGateway implements TokenBlacklistGateway {

    /**
     * Map: jti → expiration time of the revoked token.
     */
    private final Map<String, Instant> revoked = new ConcurrentHashMap<>();

    private final ClockProvider clock;

    public InMemoryTokenBlacklistGateway(ClockProvider clock) {
        this.clock = clock;
    }

    @Override
    public boolean isRevoked(String jti) {

        purgeExpired();

        Instant exp = revoked.get(jti);
        return exp != null && clock.now().isBefore(exp);
    }

    @Override
    public void revoke(String jti, Instant exp) {
        revoked.put(jti, exp);
    }

    /**
     * Removes expired entries to avoid unbounded memory growth
     * during long-running dev/test sessions.
     */
    private void purgeExpired() {
        Instant now = clock.now();
        revoked.entrySet().removeIf(e -> now.isAfter(e.getValue()));
    }
}
