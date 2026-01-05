package com.lanny.spring_security_template.infrastructure.security.redis;

import java.time.Duration;
import java.util.List;

import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

import lombok.NonNull;

/**
 * ============================================================
 * RedisRefreshTokenConsumer
 * ============================================================
 *
 * Redis-based, atomic refresh token consumer used to prevent
 * refresh token replay attacks in distributed environments.
 *
 * <p>
 * This component uses a Lua script to guarantee:
 * </p>
 *
 * <ul>
 *   <li>Atomic check-and-set semantics</li>
 *   <li>First-consumer-wins behavior</li>
 *   <li>Race-condition safety across multiple pods</li>
 * </ul>
 *
 * <h2>Why Lua instead of SETNX?</h2>
 * <p>
 * Using Lua ensures the entire operation (existence check + set + TTL)
 * executes atomically on the Redis server, avoiding subtle race conditions
 * under high contention.
 * </p>
 *
 * <h2>Key lifecycle</h2>
 * <p>
 * The consumption marker key is stored with a TTL equal to the remaining
 * lifetime of the refresh token, ensuring:
 * </p>
 *
 * <ul>
 *   <li>No unbounded key growth</li>
 *   <li>Automatic cleanup after token expiration</li>
 * </ul>
 *
 * <h2>Profiles</h2>
 * <ul>
 *   <li><b>prod</b>, <b>demo</b> → enabled</li>
 *   <li>test / local → replaced by NoOp adapter</li>
 * </ul>
 */
@Component
@Profile({ "prod", "demo" })
public class RedisRefreshTokenConsumer {

    /**
     * Redis key prefix for consumed refresh tokens.
     *
     * <p>
     * Full key format:
     * {@code security:refresh:consumed:{jti}}
     * </p>
     */
    private static final String KEY_PREFIX = "security:refresh:consumed:";

    private final StringRedisTemplate redis;
    private final @NonNull DefaultRedisScript<Long> consumeScript;

    public RedisRefreshTokenConsumer(StringRedisTemplate redis) {
        this.redis = redis;
        this.consumeScript = buildScript();
    }

    /**
     * Attempts to consume a refresh token atomically.
     *
     * @param jti unique refresh token identifier
     * @param ttl remaining lifetime of the refresh token
     * @return {@code true} if this is the first consumption attempt;
     *         {@code false} if the token was already consumed
     */
    public boolean consume(String jti, Duration ttl) {

        if (ttl == null || ttl.isZero() || ttl.isNegative()) {
            return false;
        }

        Long result = redis.execute(
                consumeScript,
                List.of(KEY_PREFIX + jti),
                String.valueOf(ttl.toSeconds())
        );

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
     *   <li>If key already exists → return 0</li>
     *   <li>Otherwise → SET key with TTL → return 1</li>
     * </ol>
     */
    private DefaultRedisScript<Long> buildScript() {

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

