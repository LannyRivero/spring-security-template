package com.lanny.spring_security_template.application.auth.port.out;

import java.time.Instant;

public interface TokenBlacklistGateway {
    boolean isRevoked(String jti);

    void revoke(String jti, Instant exp);
}
