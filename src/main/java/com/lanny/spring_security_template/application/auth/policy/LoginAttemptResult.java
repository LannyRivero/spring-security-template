package com.lanny.spring_security_template.application.auth.policy;

/**
 * Result of evaluating a login attempt against a brute-force policy.
 */
public record LoginAttemptResult(
        boolean allowed,
        long retryAfterSeconds
) {

    public static LoginAttemptResult allowAccess() {
        return new LoginAttemptResult(true, 0);
    }

    public static LoginAttemptResult blocked(long retryAfterSeconds) {
        return new LoginAttemptResult(false, retryAfterSeconds);
    }
}

