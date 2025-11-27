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
 * <p><strong>Responsibilities:</strong></p>
 * <ul>
 *   <li>Track failed login attempts per username.</li>
 *   <li>Determine if a user is currently locked out.</li>
 *   <li>Reset counters after a successful login.</li>
 * </ul>
 *
 * <p><strong>Enterprise recommendations:</strong></p>
 * <ul>
 *   <li>Redis-based implementation is ideal for distributed applications.</li>
 *   <li>Policies should be configurable via external properties.</li>
 *   <li>Never expose lockout status to the client to prevent enumeration.</li>
 * </ul>
 */
public interface LoginAttemptPolicy {

    /**
     * Checks whether the given user is temporarily locked due to
     * excessive failed login attempts.
     *
     * @param username unique identifier of the user attempting to authenticate
     * @return {@code true} if the user is locked and should be prevented from logging in
     */
    boolean isUserLocked(String username);

    /**
     * Records a failed login attempt for the given user.
     * <p>
     * Implementations should increment a counter and, if the threshold is reached,
     * start a lockout period.
     * </p>
     *
     * @param username user whose attempt failed
     */
    void recordFailedAttempt(String username);

    /**
     * Resets the failed attempt counter for the given user.
     * <p>
     * Called automatically after a successful authentication.
     * </p>
     *
     * @param username user whose attempts should be reset
     */
    void resetAttempts(String username);
}

