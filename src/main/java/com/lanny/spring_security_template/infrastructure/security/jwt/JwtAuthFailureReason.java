package com.lanny.spring_security_template.infrastructure.security.jwt;

public enum JwtAuthFailureReason {
    MISSING_TOKEN,
    INVALID_FORMAT,
    INVALID_SIGNATURE,
    INVALID_CREDENTIALS,
    TOKEN_EXPIRED,
    TOKEN_REVOKED,
    INVALID_CLAIMS,
    INVALID_TYPE,
    ACCESS_DENIED,
    NO_AUTHORITIES,
    UNKNOWN
}
