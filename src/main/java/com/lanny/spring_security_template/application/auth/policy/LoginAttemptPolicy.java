package com.lanny.spring_security_template.application.auth.policy;

/**
 * Defines the policy for detecting and mitigating brute-force login attempts.
 *
 * <p>
 * This policy determines how failed authentication attempts are tracked,
 * how many are tolerated before a temporary lockout, and how long
 * the user remains locked.
 * </p>
 *
 * <p>
 * Implementations may use any persistence mechanism — e.g. Redis, JPA, or
 * an in-memory cache — to store login attempts and enforce TTL-based unlocks.
 * </p>
 *
 * <p>
 * <strong>Responsibilities:</strong>
 * </p>
 * <ul>
 * <li>Track failed login attempts per username.</li>
 * <li>Determine if a user is currently locked out.</li>
 * <li>Reset counters after a successful login.</li>
 * </ul>
 *
 * <p>
 * <strong>Enterprise recommendations:</strong>
 * </p>
 * <ul>
 * <li>Redis-based implementation is ideal for distributed applications.</li>
 * <li>Policies should be configurable via external properties.</li>
 * <li>Never expose lockout status to the client to prevent enumeration.</li>
 * </ul>
 */
public interface LoginAttemptPolicy {

    /**
     * Registers a login attempt and decides whether the request
     * must be blocked.
     *
     * <p>
     * This operation MUST be atomic in distributed implementations.
     * </p>
     *
     * @param key rate-limit key (username, ip, or composite)
     * @return evaluation result
     */
    LoginAttemptResult registerAttempt(String key);

    /**
     * Resets the attempts after a successful authentication.
     */
    void resetAttempts(String key);
}
