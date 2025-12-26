package com.lanny.spring_security_template.infrastructure.security.policy;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.policy.LoginAttemptPolicy;
import com.lanny.spring_security_template.application.auth.policy.LoginAttemptResult;

@Component
@Profile({ "dev", "test", "demo" })
public class InMemoryLoginAttemptPolicy implements LoginAttemptPolicy {

    private final Map<String, Integer> attempts = new ConcurrentHashMap<>();

    private static final int MAX_ATTEMPTS = 3;

    @Override
    public LoginAttemptResult registerAttempt(String key) {
        int count = attempts.merge(key, 1, (oldValue, newValue) -> oldValue + newValue);

        if (count > MAX_ATTEMPTS) {
            return new LoginAttemptResult(true, 60);
        }

        return new LoginAttemptResult(false, 0);
    }

    @Override
    public void resetAttempts(String key) {
        attempts.remove(key);
    }
}
