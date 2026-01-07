package com.lanny.spring_security_template.application.auth.policy;

/**
 * Defines the policy for detecting and mitigating brute-force login attempts.
 *
 * <p>
 * This policy represents an application-level security rule that decides
 * whether authentication attempts should be temporarily blocked.
 * </p>
 *
 * <h2>Key characteristics</h2>
 * <ul>
 * <li>Framework-agnostic (no Spring, no HTTP)</li>
 * <li>Storage-agnostic (Redis, DB, cache, etc.)</li>
 * <li>Deterministic and fully testable</li>
 * </ul>
 *
 * <h2>Rate-limiting key</h2>
 * <p>
 * The {@code key} uniquely identifies the subject being rate-limited.
 * It may represent:
 * </p>
 * <ul>
 * <li>An IP address</li>
 * <li>A username</li>
 * <li>A composite key (e.g. IP + user)</li>
 * </ul>
 *
 * <p>
 * Key generation is delegated to infrastructure components
 * (e.g. {@code RateLimitKeyResolver}).
 * </p>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>No client-facing information leakage</li>
 * <li>No logging or auditing responsibilities</li>
 * <li>Atomic state transitions in distributed environments</li>
 * </ul>
 *
 * <h2>Enterprise recommendations</h2>
 * <ul>
 * <li>Use Redis or another centralized store in clustered deployments</li>
 * <li>Configure limits and TTLs via external configuration</li>
 * <li>Never expose lockout state directly to the client</li>
 * </ul>
 */
public interface LoginAttemptPolicy {

    /**
     * Registers a login attempt and evaluates whether further attempts
     * should be allowed.
     *
     * <p>
     * This operation MUST be atomic in distributed implementations
     * to prevent race conditions.
     * </p>
     *
     * @param key rate-limit key identifying the subject
     * @return evaluation result containing allow/block decision
     */
    LoginAttemptResult registerAttempt(String key);

    /**
     * Resets all tracked attempts for the given key.
     *
     * <p>
     * This method is expected to be invoked after a successful
     * authentication or other security events that invalidate
     * previous failures (e.g. password change).
     * </p>
     *
     * @param key rate-limit key identifying the subject
     */
    void resetAttempts(String key);
}
