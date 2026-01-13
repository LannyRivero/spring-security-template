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
 * Redis-based, atomic refresh token consumer used to prevent
 * refresh token replay attacks in distributed environments.
 *
 * <p>
 * Guarantees:
 * </p>
 * <ul>
 * <li>Atomic check-and-set semantics (Lua)</li>
 * <li>First-consumer-wins behavior</li>
 * <li>Race-condition safety across multiple pods</li>
 * </ul>
 *
 * <h2>Key lifecycle</h2>
 * <p>
 * The consumption marker key is stored with a TTL equal to the remaining
 * lifetime of the refresh token. Redis handles cleanup automatically.
 * </p>
 *
 * <h2>Profiles</h2>
 * <ul>
 * <li><b>prod</b>, <b>demo</b> → enabled</li>
 * <li>test / local → replaced by NoOp adapter</li>
 * </ul>
 */
@Component
@Profile({ "prod", "demo" })
public class RedisRefreshTokenConsumer {

    /**
     * Redis key prefix for consumed refresh tokens.
     *
     * <p>
     * Namespaced by issuer to avoid collisions across services/environments.
     * </p>
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
        this.redis = redis;
        this.issuer = props.issuer();
        this.consumeScript = buildScript();
    }

    /**
     * Attempts to consume a refresh token atomically.
     *
     * @param jti unique refresh token identifier
     * @param ttl remaining lifetime of the refresh token
     *
     * @return {@code true} → first successful consumption (valid token)
     *         {@code false} → token already consumed (replay attempt)
     *
     * @throws IllegalArgumentException if ttl is null, zero or negative
     *                                  (indicates an upstream bug)
     */
    public boolean consume(String jti, Duration ttl) {

        if (ttl == null || ttl.isZero() || ttl.isNegative()) {
            throw new IllegalArgumentException("Refresh token TTL must be positive");
        }

        String key = String.format(KEY_PREFIX, issuer) + jti;
        List<String> keys = List.of(key);

        Long result = redis.execute(
                Objects.requireNonNull(consumeScript),
                Objects.requireNonNull(keys),
                String.valueOf(ttl.toSeconds()));

        return result != null && result == 1L;
    }

    /**
     * Builds the Lua script used for atomic refresh token consumption.
     *
     * <p>
     * Script semantics:
     * </p>
     *
     * <ol>
     * <li>If key already exists → return 0</li>
     * <li>Otherwise → SET key with TTL → return 1</li>
     * </ol>
     */
    private RedisScript<Long> buildScript() {

        String lua = """
                if redis.call('EXISTS', KEYS[1]) == 1 then
                    return 0
                end
                redis.call('SET', KEYS[1], '1', 'EX', ARGV[1])
                return 1
                """;

        DefaultRedisScript<Long> script = new DefaultRedisScript<>();
        script.setScriptText(lua);
        script.setResultType(Long.class);
        return script;
    }
}
