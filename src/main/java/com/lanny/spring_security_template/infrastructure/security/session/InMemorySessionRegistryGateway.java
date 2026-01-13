package com.lanny.spring_security_template.infrastructure.security.session;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.port.out.SessionRegistryGateway;

/**
 * ============================================================
 * InMemorySessionRegistryGateway
 * ============================================================
 *
 * <p>
 * In-memory implementation of {@link SessionRegistryGateway} intended
 * exclusively for development and testing environments.
 * </p>
 *
 * <h2>Purpose</h2>
 * <p>
 * This registry tracks active user sessions without persistence and
 * without automatic expiration cleanup. It exists to:
 * </p>
 * <ul>
 * <li>Support local development</li>
 * <li>Enable deterministic tests</li>
 * <li>Avoid infrastructure dependencies (e.g. Redis)</li>
 * </ul>
 *
 * <h2>Non-production usage</h2>
 * <p>
 * This implementation MUST NOT be used in production environments.
 * Production deployments must rely on a persistent, distributed
 * session registry.
 * </p>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Thread-safe via {@link ConcurrentHashMap}</li>
 * <li>No background cleanup or TTL enforcement</li>
 * <li>Expired sessions are filtered on read</li>
 * </ul>
 */
@Component
@Profile({ "dev", "test" })
public class InMemorySessionRegistryGateway implements SessionRegistryGateway {

    private final Map<String, Map<String, Instant>> registry = new ConcurrentHashMap<>();

    @Override
    public void registerSession(String username, String jti, Instant expiresAt) {
        registry
                .computeIfAbsent(username, k -> new ConcurrentHashMap<>())
                .put(jti, expiresAt);
    }

    @Override
    public List<String> getActiveSessions(String username) {
        Instant now = Instant.now();

        Map<String, Instant> sessions = registry.get(username);
        if (sessions == null) {
            return List.of();
        }

        return sessions.entrySet().stream()
                .filter(entry -> entry.getValue().isAfter(now))
                .map(Map.Entry::getKey)
                .toList();
    }

    @Override
    public void removeSession(String username, String jti) {
        Map<String, Instant> sessions = registry.get(username);
        if (sessions != null) {
            sessions.remove(jti);
        }
    }

    @Override
    public void removeAllSessions(String username) {
        registry.remove(username);
    }

    @Override
    public int countSessions(String username) {
        Map<String, Instant> sessions = registry.get(username);
        return sessions != null ? sessions.size() : 0;
    }
}
