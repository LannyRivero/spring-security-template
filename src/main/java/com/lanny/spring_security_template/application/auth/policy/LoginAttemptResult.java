package com.lanny.spring_security_template.application.auth.policy;

public record LoginAttemptResult(
        boolean blocked,
        long retryAfterSeconds) {
}
