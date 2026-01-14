package com.lanny.spring_security_template.infrastructure.security.redis;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;

/**
 * ============================================================
 * RedisRefreshTokenConsumer
 * ============================================================
 *
 * Single source of truth for refresh token replay protection.
 *
 * <p>
 * Provides atomic, Redis-backed "consume-once" semantics for refresh
 * tokens using Lua scripting.
 * </p>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>First-consumer-wins semantics</li>
 * <li>Replay attempts are reliably detected</li>
 * <li>Safe under concurrent, multi-instance deployments</li>
 * </ul>
 *
 * <h2>Operational guarantees</h2>
 * <ul>
 * <li>Single Redis key prefix</li>
 * <li>Issuer-aware namespacing</li>
 * <li>Single TTL unit: milliseconds</li>
 * </ul>
 *
 * <h2>Profiles</h2>
 * <ul>
 * <li><b>prod</b>, <b>demo</b></li>
 * </ul>
 */
@Component
@Profile({ "prod", "demo" })
public final class RedisRefreshTokenConsumer {

    /**
     * Redis key prefix for refresh token consumption markers.
     *
     * <pre>
     * security:{issuer}:refresh:consumed:{jti}
     * </pre>
     */
    private static final String KEY_PREFIX = "security:%s:refresh:consumed:";

    private final StringRedisTemplate redis;
    private final RedisScript<Long> consumeScript;
    private final String issuer;

    public RedisRefreshTokenConsumer(
            StringRedisTemplate redis,
            SecurityJwtProperties props) {

        this.redis = Objects.requireNonNull(redis, "redis");
        this.issuer = Objects.requireNonNull(props.issuer(), "issuer");
        this.consumeScript = buildScript();
    }

    /**
     * Atomically consumes a refresh token identifier (JTI).
     *
     * @param jti          unique refresh token identifier
     * @param remainingTtl remaining lifetime of the refresh token
     * @return {@code true} if consumed for the first time, {@code false} if replay
     *         detected
     */
    public boolean consumeOnce(String jti, Duration remainingTtl) {

        if (jti == null || jti.isBlank()) {
            throw new IllegalArgumentException("Refresh token JTI must not be blank");
        }

        if (remainingTtl == null || remainingTtl.isZero() || remainingTtl.isNegative()) {
            // Secure by default: expired or invalid TTL => reject
            return false;
        }

        long ttlMillis = remainingTtl.toMillis();
        if (ttlMillis <= 0) {
            return false;
        }

        String key = String.format(KEY_PREFIX, issuer) + jti;

        Long result = redis.execute(
                Objects.requireNonNull(consumeScript, "consumeScript"),
                Objects.requireNonNull(List.of(key), "keys"),
                String.valueOf(ttlMillis));

        return result != null && result == 1L;
    }

    private RedisScript<Long> buildScript() {

        String lua = """
                if redis.call("SETNX", KEYS[1], "1") == 1 then
                  redis.call("PEXPIRE", KEYS[1], ARGV[1])
                  return 1
                end
                return 0
                """;

        DefaultRedisScript<Long> script = new DefaultRedisScript<>();
        script.setScriptText(lua);
        script.setResultType(Long.class);
        return script;
    }
}
