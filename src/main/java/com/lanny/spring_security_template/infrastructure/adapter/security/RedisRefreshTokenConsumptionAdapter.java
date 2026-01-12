package com.lanny.spring_security_template.infrastructure.adapter.security;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenConsumptionPort;

/**
 * ============================================================
 * RedisRefreshTokenConsumptionAdapter
 * ============================================================
 *
 * Infrastructure adapter that connects the Application Layer
 * with the Redis-based refresh token consumer.
 *
 * <p>
 * This adapter translates the high-level application contract
 * ({@link RefreshTokenConsumptionPort}) into a concrete Redis
 * implementation using atomic Lua execution.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Delegate refresh token consumption to Redis</li>
 * <li>Preserve Clean Architecture boundaries</li>
 * <li>Remain free of business logic</li>
 * </ul>
 *
 * <h2>Profiles</h2>
 * <ul>
 * <li><b>prod</b>, <b>demo</b> → Redis-backed implementation</li>
 * <li>test / local → replaced by NoOp adapter</li>
 * </ul>
 */
@Component
@Profile("prod")
public class RedisRefreshTokenConsumptionAdapter
    implements RefreshTokenConsumptionPort {

  private static final String KEY_PREFIX = "refresh:consume:";

  private final StringRedisTemplate redis;
  private final RedisScript<Long> script;

  public RedisRefreshTokenConsumptionAdapter(StringRedisTemplate redis) {
    this.redis = redis;
    this.script = RedisScript.of("""
            if redis.call("SETNX", KEYS[1], "1") == 1 then
              redis.call("PEXPIRE", KEYS[1], ARGV[1])
              return 1
            else
              return 0
            end
        """, Long.class);

  }

  @Override
  public boolean consume(String jti, Duration remainingTtl) {

    String key = KEY_PREFIX + jti;
    long ttlMillis = remainingTtl.toMillis();
    List<String> keys = List.of(key);

    Long result = redis.execute(
        Objects.requireNonNull(script),
        Objects.requireNonNull(keys),
        String.valueOf(ttlMillis));

    return result != null && result == 1;
  }
}
