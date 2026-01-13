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
 * <p>
 * Redis-based, atomic refresh token consumer used to prevent refresh token
 * replay attacks in distributed environments.
 * </p>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>Atomic check-and-set semantics via Redis Lua scripting</li>
 * <li>First-consumer-wins behavior</li>
 * <li>Safe under concurrent, multi-instance deployments</li>
 * </ul>
 *
 * <h2>Key lifecycle</h2>
 * <p>
 * A consumption marker key is stored with a TTL equal to the remaining lifetime
 * of the refresh token. Redis automatically removes expired markers.
 * </p>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>This component only marks consumption</li>
 * <li>Token family revocation and reactions are handled elsewhere</li>
 * <li>No background jobs or schedulers are required</li>
 * </ul>
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
     * @param jti unique refresh token identifier (must not be null or blank)
     * @param ttl remaining lifetime of the refresh token
     *
     * @return {@code true} if this call successfully consumed the token
     *         {@code false} if the token was already consumed
     *
     * @throws IllegalArgumentException if {@code jti} is null or blank,
     *                                  or if {@code ttl} is null, zero or negative
     */
    public boolean consume(String jti, Duration ttl) {

        if (jti == null || jti.isBlank()) {
            throw new IllegalArgumentException("Refresh token JTI must not be null or blank");
        }

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
     * <ol>
     * <li>If the key already exists → return 0</li>
     * <li>Otherwise → SET key with TTL (NX) → return 1</li>
     * </ol>
     */
    private RedisScript<Long> buildScript() {

        String lua = """
                if redis.call('SET', KEYS[1], '1', 'EX', ARGV[1], 'NX') then
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
