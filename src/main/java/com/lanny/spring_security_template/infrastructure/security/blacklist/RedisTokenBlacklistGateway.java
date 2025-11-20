package com.lanny.spring_security_template.infrastructure.security.blacklist;

import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import lombok.RequiredArgsConstructor;

import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.Duration;
import java.util.Objects;

@Component
@Profile({ "prod", "demo" })
@RequiredArgsConstructor
public class RedisTokenBlacklistGateway implements TokenBlacklistGateway {

    private final StringRedisTemplate redis;
    private static final String PREFIX = "blacklist:jti:";    

     @Override
    public void revoke(String jti, Instant expiresAt) {
        long ttl = Duration.between(Instant.now(), expiresAt).toSeconds();
        redis.opsForValue().set(PREFIX + jti, "revoked", Objects.requireNonNull(Duration.ofSeconds(ttl)));
    }

    @Override
    public boolean isRevoked(String jti) {
        return Boolean.TRUE.equals(redis.hasKey(PREFIX + jti));
    }
}
