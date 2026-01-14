package com.lanny.spring_security_template.infrastructure.adapter.security;

import java.time.Duration;
import java.util.Objects;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenConsumptionPort;
import com.lanny.spring_security_template.infrastructure.security.redis.RedisRefreshTokenConsumer;

/**
 * ============================================================
 * RedisRefreshTokenConsumptionAdapter
 * ============================================================
 *
 * Thin infrastructure adapter that delegates refresh token
 * consumption to {@link RedisRefreshTokenConsumer}.
 *
 * <p>
 * This class contains NO Redis logic, NO scripts, NO prefixes.
 * </p>
 */
@Component
@Profile({ "prod", "demo" })
public final class RedisRefreshTokenConsumptionAdapter
    implements RefreshTokenConsumptionPort {

  private final RedisRefreshTokenConsumer consumer;

  public RedisRefreshTokenConsumptionAdapter(RedisRefreshTokenConsumer consumer) {
    this.consumer = Objects.requireNonNull(consumer, "consumer");
  }

  @Override
  public boolean consume(String jti, Duration remainingTtl) {
    return consumer.consumeOnce(jti, remainingTtl);
  }
}
