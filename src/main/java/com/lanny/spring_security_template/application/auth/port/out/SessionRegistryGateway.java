package com.lanny.spring_security_template.application.auth.port.out;

import java.time.Instant;
import java.util.List;

public interface SessionRegistryGateway {

    void registerSession(String username, String jti, Instant expiresAt);

    List<String> getActiveSessions(String username);

    void removeSession(String username, String jti);

    void removeAllSessions(String username);

    int countSessions(String username);
}
