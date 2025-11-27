package com.lanny.spring_security_template.application.auth.policy;

public interface RotationPolicy {

    /**
     * Indica si la rotación de refresh tokens está activada.
     */
    boolean isRotationEnabled();
}
