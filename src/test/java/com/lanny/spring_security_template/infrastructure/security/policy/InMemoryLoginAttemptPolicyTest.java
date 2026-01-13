package com.lanny.spring_security_template.infrastructure.security.policy;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.lanny.spring_security_template.application.auth.policy.LoginAttemptResult;
import com.lanny.spring_security_template.domain.time.ClockProvider;
import com.lanny.spring_security_template.infrastructure.config.RateLimitingProperties;
import com.lanny.spring_security_template.infrastructure.security.ratelimit.RateLimitStrategy;

class InMemoryLoginAttemptPolicyTest {

    static final class MutableClock implements ClockProvider {
        private Instant now;
        MutableClock(Instant now) { this.now = now; }
        @Override public java.time.Clock clock() { return java.time.Clock.fixed(now, java.time.ZoneOffset.UTC); }
        @Override public Instant now() { return now; }
        @Override public Instant plusSeconds(long seconds) { now = now.plusSeconds(seconds); return now; }
    }

    @Test
    @DisplayName("allows attempts up to maxAttempts, blocks on maxAttempts+1, then unblocks after blockSeconds")
    void allowsThenBlocksThenUnblocks() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-10T10:00:00Z"));

        RateLimitingProperties props = new RateLimitingProperties(
                true,
                RateLimitStrategy.IP,
                3,      // maxAttempts
                60,     // window seconds
                60,     // blockSeconds
                60,     // retryAfter
                "/api/v1/auth/login"
        );

        InMemoryLoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy(clock, props);
        String key = "k";

        // attempts 1..3 allowed
        assertTrue(policy.registerAttempt(key).allowed());
        assertTrue(policy.registerAttempt(key).allowed());
        assertTrue(policy.registerAttempt(key).allowed());

        // 4th => blocked
        LoginAttemptResult blocked = policy.registerAttempt(key);
        assertFalse(blocked.allowed());
        assertTrue(blocked.retryAfterSeconds() > 0);

        // during block => still blocked
        clock.plusSeconds(10);
        LoginAttemptResult stillBlocked = policy.registerAttempt(key);
        assertFalse(stillBlocked.allowed());
        assertTrue(stillBlocked.retryAfterSeconds() > 0);

        // after block duration => allowed again (new window starts)
        clock.plusSeconds(60);
        LoginAttemptResult allowedAgain = policy.registerAttempt(key);
        assertTrue(allowedAgain.allowed());
        assertEquals(0, allowedAgain.retryAfterSeconds());
    }

    @Test
    @DisplayName("resetAttempts clears state immediately")
    void testShouldResetClearsState() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-10T10:00:00Z"));

        RateLimitingProperties props = new RateLimitingProperties(
                true, RateLimitStrategy.IP, 3, 60, 60, 60, "/api/v1/auth/login"
        );

        InMemoryLoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy(clock, props);
        String key = "k";

        policy.registerAttempt(key);
        policy.registerAttempt(key);

        policy.resetAttempts(key);

        LoginAttemptResult afterReset = policy.registerAttempt(key);
        assertTrue(afterReset.allowed());
        assertEquals(0, afterReset.retryAfterSeconds());
    }

    @Test
    @DisplayName("window expiration resets attempt counter")
    void testShouldWindowExpirationResetsAttempts() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-10T10:00:00Z"));

        RateLimitingProperties props = new RateLimitingProperties(
                true, RateLimitStrategy.IP, 3, 60, 60, 60, "/api/v1/auth/login"
        );

        InMemoryLoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy(clock, props);
        String key = "k";

        // 2 attempts now
        assertTrue(policy.registerAttempt(key).allowed());
        assertTrue(policy.registerAttempt(key).allowed());

        // move past window
        clock.plusSeconds(61);

        // should be treated as new window, allowed
        LoginAttemptResult result = policy.registerAttempt(key);
        assertTrue(result.allowed());
    }
}
