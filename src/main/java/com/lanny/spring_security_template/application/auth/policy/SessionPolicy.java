package com.lanny.spring_security_template.application.auth.policy;

public interface SessionPolicy {

    /**
     * Número máximo de sesiones concurrentes permitidas por usuario.
     */
    int maxSessionsPerUser();
}
