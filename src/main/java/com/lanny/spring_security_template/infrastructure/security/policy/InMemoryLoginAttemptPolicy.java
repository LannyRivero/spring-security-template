package com.lanny.spring_security_template.infrastructure.security.policy;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.policy.LoginAttemptPolicy;
import com.lanny.spring_security_template.application.auth.policy.LoginAttemptResult;

/**
 * {@code InMemoryLoginAttemptPolicy}
 *
 * <h2>Purpose</h2>
 * In-memory implementation of {@link LoginAttemptPolicy} intended exclusively
 * for non-production environments.
 *
 * <h2>Intended usage</h2>
 * <ul>
 * <li>Local development</li>
 * <li>Unit and integration tests</li>
 * <li>Demo environments without Redis</li>
 * </ul>
 *
 * <h2>Security notes</h2>
 * <ul>
 * <li>This implementation is <b>NOT</b> distributed.</li>
 * <li>State is lost on application restart.</li>
 * <li>Must never be enabled in production.</li>
 * </ul>
 *
 * <h2>Behavior</h2>
 * <ul>
 * <li>Tracks attempts per key within a fixed time window.</li>
 * <li>Applies a temporary block when the threshold is exceeded.</li>
 * <li>Automatically expires counters and blocks based on timestamps.</li>
 * </ul>
 */
@Component
@Profile({ "dev", "test", "demo" })
public class InMemoryLoginAttemptPolicy implements LoginAttemptPolicy {

    private static final int MAX_ATTEMPTS = 3;
    private static final Duration WINDOW = Duration.ofMinutes(1);
    private static final Duration BLOCK_DURATION = Duration.ofSeconds(60);

    private final Map<String, AttemptState> store = new ConcurrentHashMap<>();

    @Override
    public LoginAttemptResult registerAttempt(String key) {

        Instant now = Instant.now();

        AttemptState state = store.compute(key, (k, existing) -> {
            if (existing == null || existing.isExpired(now)) {
                return AttemptState.newWindow(now);
            }
            return existing.increment();
        });

        if (state.isBlocked(now)) {
            return new LoginAttemptResult(
                    true,
                    state.secondsUntilUnblock(now));
        }

        if (state.attempts > MAX_ATTEMPTS) {
            state.blockUntil = now.plus(BLOCK_DURATION);
            return new LoginAttemptResult(true, BLOCK_DURATION.getSeconds());
        }

        return new LoginAttemptResult(false, 0);
    }

    @Override
    public void resetAttempts(String key) {
        store.remove(key);
    }

    // ======================================================
    // Internal state
    // ======================================================

    private static final class AttemptState {

        int attempts;
        Instant windowStart;
        Instant blockUntil;

        static AttemptState newWindow(Instant now) {
            AttemptState s = new AttemptState();
            s.attempts = 1;
            s.windowStart = now;
            return s;
        }

        AttemptState increment() {
            this.attempts++;
            return this;
        }

        boolean isExpired(Instant now) {
            return windowStart.plus(WINDOW).isBefore(now);
        }

        boolean isBlocked(Instant now) {
            return blockUntil != null && blockUntil.isAfter(now);
        }

        long secondsUntilUnblock(Instant now) {
            return blockUntil != null
                    ? Math.max(0, blockUntil.getEpochSecond() - now.getEpochSecond())
                    : 0;
        }
    }
}
