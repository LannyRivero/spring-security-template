package com.lanny.spring_security_template.infrastructure.security.jwt;

public enum JwtAuthFailureReason {
    MISSING_TOKEN,
    INVALID_FORMAT,
    INVALID_SIGNATURE,
    TOKEN_EXPIRED,
    INVALID_CLAIMS,
    ACCESS_DENIED,
    UNKNOWN
}
