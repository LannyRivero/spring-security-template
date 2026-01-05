package com.lanny.spring_security_template.infrastructure.adapter.security;

import java.time.Duration;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenConsumptionPort;
import com.lanny.spring_security_template.infrastructure.security.redis.RedisRefreshTokenConsumer;

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
@Profile({ "prod", "demo" })
public class RedisRefreshTokenConsumptionAdapter
        implements RefreshTokenConsumptionPort {

    private final RedisRefreshTokenConsumer consumer;

    public RedisRefreshTokenConsumptionAdapter(
            RedisRefreshTokenConsumer consumer) {
        this.consumer = consumer;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean consume(String jti, Duration remainingTtl) {
        return consumer.consume(jti, remainingTtl);
    }
}
