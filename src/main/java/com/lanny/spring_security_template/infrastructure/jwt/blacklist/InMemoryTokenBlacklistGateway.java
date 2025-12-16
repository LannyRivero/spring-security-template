package com.lanny.spring_security_template.infrastructure.jwt.blacklist;

import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory blacklist for revoked JWTs.
 *
 * <p>
 * This implementation is intended exclusively for <b>dev</b> and <b>test</b>
 * profiles. It stores revoked JWT IDs (jti) in a thread-safe map, together
 * with their expiration timestamps.
 * </p>
 *
 * <p>
 * <b>NOT FOR PRODUCTION</b> — in real deployments, use Redis or another
 * distributed storage to ensure consistency across instances.
 * </p>
 */
@Component
@Profile({ "dev", "test" })
public class InMemoryTokenBlacklistGateway implements TokenBlacklistGateway {

    /**
     * Map: jti → expiration time of the revoked token.
     */
    private final Map<String, Instant> revoked = new ConcurrentHashMap<>();

    @Override
    public boolean isRevoked(String jti) {

        purgeExpired();

        Instant exp = revoked.get(jti);
        return exp != null && Instant.now().isBefore(exp);
    }

    @Override
    public void revoke(String jti, Instant exp) {
        revoked.put(jti, exp);
    }

    /**
     * Removes entries whose expiration time has already passed.
     * Prevents unbounded growth during long-running dev/test sessions.
     */
    private void purgeExpired() {
        Instant now = Instant.now();
        revoked.entrySet().removeIf(e -> now.isAfter(e.getValue()));
    }
}
