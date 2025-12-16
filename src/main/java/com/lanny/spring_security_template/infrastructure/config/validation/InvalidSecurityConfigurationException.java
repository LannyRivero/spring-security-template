package com.lanny.spring_security_template.infrastructure.config.validation;

public class InvalidSecurityConfigurationException extends RuntimeException {

    public InvalidSecurityConfigurationException(String message) {
        super(message);
    }

    public InvalidSecurityConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
