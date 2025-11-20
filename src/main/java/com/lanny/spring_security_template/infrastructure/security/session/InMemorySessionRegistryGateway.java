package com.lanny.spring_security_template.infrastructure.security.session;

import com.lanny.spring_security_template.application.auth.port.out.SessionRegistryGateway;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Component
@Profile({ "dev", "test" })
public class InMemorySessionRegistryGateway implements SessionRegistryGateway {

    private final Map<String, Map<String, Instant>> registry = new ConcurrentHashMap<>();

    @Override
    public void registerSession(String username, String jti, Instant expiresAt) {
        registry.computeIfAbsent(username, k -> new ConcurrentHashMap<>())
                .put(jti, expiresAt);
    }

    @Override
    public List<String> getActiveSessions(String username) {
        return registry.getOrDefault(username, Map.of()).keySet().stream().toList();
    }

    @Override
    public void removeSession(String username, String jti) {
        registry.getOrDefault(username, Map.of()).remove(jti);
    }

    @Override
    public void removeAllSessions(String username) {
        registry.remove(username);
    }

    @Override
    public int countSessions(String username) {
        return registry.getOrDefault(username, Map.of()).size();
    }
}
