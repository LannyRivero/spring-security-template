package com.lanny.spring_security_template.application.auth.port.out;

import java.time.Instant;
import java.util.List;

public interface RefreshTokenStore {

    void save(String username, String jti, Instant issuedAt, Instant expiresAt);

    boolean exists(String jti);

    void delete(String jti);

    void deleteAllForUser(String username);

    List<String> findAllForUser(String username);
}

