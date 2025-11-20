package com.lanny.spring_security_template.infrastructure.security.redis;

import com.lanny.spring_security_template.application.auth.port.out.BlacklistCleanupGateway;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

@Component
@Profile("prod-redis")
@RequiredArgsConstructor
public class BlacklistCleanupRedisAdapter implements BlacklistCleanupGateway {

    private final RedisTemplate<String, String> redis;

    @Override
    public List<String> findExpired(Instant now) {

        // Estructura: blacklist:<jti> = expiresAt
        var keys = redis.keys("blacklist:*");
        if (keys == null || keys.isEmpty()) return List.of();

        return keys.stream()
                .filter(key -> {
                    Object expStrObj = redis.opsForValue().get(key);
                    if (expStrObj == null) return true;
                    String expStr = expStrObj.toString();
                    long exp = Long.parseLong(expStr);
                    return exp < now.getEpochSecond();
                })
                .map(key -> key.replace("blacklist:", ""))
                .toList();
    }

    @Override
    public void delete(String jti) {
        redis.delete("blacklist:" + jti);
    }
}
