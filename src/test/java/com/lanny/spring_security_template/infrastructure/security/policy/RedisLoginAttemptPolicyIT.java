package com.lanny.spring_security_template.infrastructure.security.policy;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.lanny.spring_security_template.application.auth.policy.LoginAttemptResult;
import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;
import com.lanny.spring_security_template.infrastructure.config.RateLimitingProperties;
import com.lanny.spring_security_template.infrastructure.security.ratelimit.RateLimitStrategy;

@Testcontainers
class RedisLoginAttemptPolicyIT {

    @Container
    static final GenericContainer<?> redis = new GenericContainer<>("redis:7.2-alpine")
            .withExposedPorts(6379);

    static class MetricsStub implements AuthMetricsService {
        int bruteForceDetected = 0;

        @Override
        public void recordLoginSuccess() {
        }

        @Override
        public void recordLoginFailure() {
        }

        @Override
        public void recordBruteForceDetected() {
            bruteForceDetected++;
        }

        @Override
        public void recordPasswordChange() {
        }

        @Override
        public void recordSessionRevoked() {
        }

        @Override
        public void recordRefreshReused() {
        }

        @Override
        public void recordTokenRefresh() {
        }

        @Override
        public void recordUserRegistration() {
        }

        @Override
        public void recordRotationFailed() {
        }

        @Override
        public void recordUserLocked() {
        }
    }

    private StringRedisTemplate redisTemplate() {
        String host = redis.getHost();
        Integer port = redis.getMappedPort(6379);

        LettuceConnectionFactory factory = new LettuceConnectionFactory(host, port);
        factory.afterPropertiesSet();

        StringRedisTemplate template = new StringRedisTemplate(factory);
        template.afterPropertiesSet();
        return template;
    }

    @Test
    @DisplayName("allows attempts up to maxAttempts, blocks on maxAttempts+1 and reset clears block")
    void allowsThenBlocksThenReset() {
        StringRedisTemplate template = redisTemplate();

        RateLimitingProperties props = new RateLimitingProperties(
                true,
                RateLimitStrategy.IP_USER,
                3, // maxAttempts
                60, // window
                60, // blockSeconds
                60, // retryAfter
                "/api/v1/auth/login");

        MetricsStub metrics = new MetricsStub();
        RedisLoginAttemptPolicy policy = new RedisLoginAttemptPolicy(template, props, metrics);

        String key = "k";

        // 1..3 allowed
        assertTrue(policy.registerAttempt(key).allowed());
        assertTrue(policy.registerAttempt(key).allowed());
        assertTrue(policy.registerAttempt(key).allowed());

        // 4th blocked
        LoginAttemptResult blocked = policy.registerAttempt(key);
        assertFalse(blocked.allowed());
        assertTrue(blocked.retryAfterSeconds() > 0);
        assertEquals(1, metrics.bruteForceDetected);

        // reset clears both attempts and block keys
        policy.resetAttempts(key);

        LoginAttemptResult afterReset = policy.registerAttempt(key);
        assertTrue(afterReset.allowed());
    }

    @Test
    @DisplayName("block TTL decreases over time (basic sanity)")
    void blockTtlDecreases() throws InterruptedException {
        StringRedisTemplate template = redisTemplate();

        RateLimitingProperties props = new RateLimitingProperties(
                true, RateLimitStrategy.IP, 1, 60, 5, 5, "/api/v1/auth/login");

        MetricsStub metrics = new MetricsStub();
        RedisLoginAttemptPolicy policy = new RedisLoginAttemptPolicy(template, props, metrics);

        String key = "ttl-test";

        // first allowed (maxAttempts=1)
        assertTrue(policy.registerAttempt(key).allowed());

        // second triggers block (attempts > 1)
        LoginAttemptResult blocked1 = policy.registerAttempt(key);
        assertFalse(blocked1.allowed());
        long ttl1 = blocked1.retryAfterSeconds();
        assertTrue(ttl1 > 0);

        Thread.sleep(1100);

        LoginAttemptResult blocked2 = policy.registerAttempt(key);
        assertFalse(blocked2.allowed());
        long ttl2 = blocked2.retryAfterSeconds();

        assertTrue(ttl2 <= ttl1);
    }
}
