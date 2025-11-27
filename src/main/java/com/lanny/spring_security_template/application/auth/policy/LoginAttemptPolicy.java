package com.lanny.spring_security_template.application.auth.policy;

public interface LoginAttemptPolicy {

    boolean isUserLocked(String username);

    void recordFailedAttempt(String username);

    void resetAttempts(String username);

}
