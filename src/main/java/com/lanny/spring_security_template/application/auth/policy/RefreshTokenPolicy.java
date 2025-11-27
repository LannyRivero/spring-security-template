package com.lanny.spring_security_template.application.auth.policy;

public interface RefreshTokenPolicy {

    /**
     * Audiencia esperada para los refresh tokens.
     */
    String expectedRefreshAudience();
}
