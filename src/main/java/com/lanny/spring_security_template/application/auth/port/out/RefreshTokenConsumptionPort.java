package com.lanny.spring_security_template.application.auth.port.out;

import java.time.Duration;

/**
 * ============================================================
 * RefreshTokenConsumptionPort
 * ============================================================
 *
 * Outbound port responsible for **atomic consumption of refresh tokens**
 * to prevent replay attacks in distributed environments.
 *
 * <p>
 * This port provides a minimal, concurrency-focused contract used during
 * the refresh token flow to ensure that a refresh token is only accepted
 * once, even under:
 * </p>
 *
 * <ul>
 * <li>Multi-pod / multi-instance deployments</li>
 * <li>Concurrent refresh attempts</li>
 * <li>Race conditions between rotation and reuse</li>
 * </ul>
 *
 * <h2>What this port DOES</h2>
 * <ul>
 * <li>Atomically marks a refresh token JTI as "consumed"</li>
 * <li>Guarantees first-writer-wins semantics</li>
 * <li>Detects refresh token replay attempts</li>
 * </ul>
 *
 * <h2>What this port DOES NOT do</h2>
 * <ul>
 * <li>No persistence of refresh token metadata</li>
 * <li>No family tracking or revocation logic</li>
 * <li>No JWT parsing or validation</li>
 * <li>No cryptographic verification</li>
 * </ul>
 *
 * <h2>Design rationale</h2>
 * <p>
 * Refresh token reuse detection is a **distributed concurrency problem**,
 * not a persistence concern. Therefore, this port is intentionally
 * separated from {@code RefreshTokenStore}.
 * </p>
 *
 * <p>
 * Typical implementations use:
 * </p>
 * <ul>
 * <li><b>Redis (SETNX / Lua)</b> — preferred for production</li>
 * <li>Database CAS (UPDATE ... WHERE) — slower, optional</li>
 * <li>In-memory — test / local only</li>
 * </ul>
 *
 * <h2>Usage in refresh flow</h2>
 * <ol>
 * <li>Validate refresh token cryptographically</li>
 * <li>Extract JTI and remaining TTL</li>
 * <li>Call {@link #consume(String, Duration)}</li>
 * <li>If {@code false} → replay detected → revoke token family</li>
 * <li>If {@code true} → continue with normal rotation</li>
 * </ol>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>Replay-safe refresh token rotation</li>
 * <li>Fail-fast detection of token reuse</li>
 * <li>Safe under concurrent and distributed execution</li>
 * </ul>
 */
public interface RefreshTokenConsumptionPort {

    /**
     * Atomically consumes a refresh token JTI.
     *
     * <p>
     * This method must guarantee that only the **first invocation**
     * for a given JTI returns {@code true}. All subsequent invocations
     * must return {@code false}, even if executed concurrently.
     * </p>
     *
     * <p>
     * The provided TTL MUST match the remaining lifetime of the refresh
     * token so that the consumption marker expires automatically.
     * </p>
     *
     * @param jti          unique identifier of the refresh token (JWT ID)
     * @param remainingTtl remaining lifetime of the refresh token
     * @return {@code true} if this is the first consumption attempt;
     *         {@code false} if the token was already consumed
     */
    boolean consume(String jti, Duration remainingTtl);
}
