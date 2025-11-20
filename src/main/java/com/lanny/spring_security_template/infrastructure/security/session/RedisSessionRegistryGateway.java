package com.lanny.spring_security_template.infrastructure.security.session;

import com.lanny.spring_security_template.application.auth.port.out.SessionRegistryGateway;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Set;

@Component
@Profile({"prod", "demo"})
public class RedisSessionRegistryGateway implements SessionRegistryGateway {

    private final RedisTemplate<String, String> redis;

    public RedisSessionRegistryGateway(RedisTemplate<String, String> redis) {
        this.redis = redis;
    }

    private @NonNull String key(@NonNull String username) {
        return "sessions:" + username;
    }

    @Override
    @SuppressWarnings("null") // RedisTemplate devuelve tipos inseguros para @NonNull
    public void registerSession(String username, String jti, Instant expiresAt) {
        redis.opsForZSet().add(key(username), jti, expiresAt.getEpochSecond());
    }

    @Override
    @SuppressWarnings("null")
    public List<String> getActiveSessions(String username) {
        Set<String> raw = redis.opsForZSet().range(key(username), 0, -1);

        if (raw == null || raw.isEmpty()) {
            return List.of();
        }

        return raw.stream()
                .filter(Objects::nonNull)
                .toList();
    }

    @Override
    @SuppressWarnings("null")
    public void removeSession(String username, String jti) {
        redis.opsForZSet().remove(key(username), jti);
    }

    @Override
    @SuppressWarnings("null")
    public void removeAllSessions(String username) {
        redis.delete(key(username));
    }

    @Override
    @SuppressWarnings("null")
    public int countSessions(String username) {
        Long size = redis.opsForZSet().size(key(username));
        return size == null ? 0 : size.intValue();
    }
}

