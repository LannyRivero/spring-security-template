package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.SessionRegistryGateway;
import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class SessionManager {

    private final SessionRegistryGateway sessionRegistry;
    private final TokenBlacklistGateway blacklist;
    private final SecurityJwtProperties props;
    private final RefreshTokenStore refreshTokenStore;

    public void register(IssuedTokens tokens) {

        String username = tokens.username();

        // Registrar nueva sesión
        sessionRegistry.registerSession(
                username,
                tokens.refreshJti(),
                tokens.refreshExp());

        int maxSessions = props.maxActiveSessions();

        if (maxSessions <= 0) {
            return; // sin límite
        }

        List<String> sessions = sessionRegistry.getActiveSessions(username);

        if (sessions.size() <= maxSessions) {
            return;
        }

        int excess = sessions.size() - maxSessions;

        for (int i = 0; i < excess; i++) {
            String jtiToRemove = sessions.get(i);

            // Revocamos el refresh antiguo
            blacklist.revoke(jtiToRemove, tokens.refreshExp());

            // Eliminamos del registry
            sessionRegistry.removeSession(username, jtiToRemove);

            // Eliminamos de BD
            refreshTokenStore.delete(jtiToRemove);
        }
    }
}
