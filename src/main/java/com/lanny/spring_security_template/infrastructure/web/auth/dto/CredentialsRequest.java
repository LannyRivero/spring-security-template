package com.lanny.spring_security_template.infrastructure.web.auth.dto;

/**
 * Defines a contract for credential request DTOs.
 */
public interface CredentialsRequest {
    String getUsername();

    String getPassword();
}
