package com.lanny.spring_security_template.infrastructure.security.ratelimit;

import org.springframework.stereotype.Component;

/**
 * ============================================================
 * RateLimitKeyResolverFactory
 * ============================================================
 *
 * <p>
 * Factory responsible for selecting the appropriate
 * {@link RateLimitKeyResolver} based on the configured
 * {@link RateLimitStrategy}.
 * </p>
 *
 * <h2>Responsibility</h2>
 * <p>
 * This class performs <b>selection only</b>.
 * It does not contain any rate-limiting logic, hashing logic,
 * or request parsing.
 * </p>
 *
 * <p>
 * All key derivation logic is delegated to dedicated
 * {@link RateLimitKeyResolver} implementations, each one
 * encapsulating a single, well-defined strategy.
 * </p>
 *
 * <h2>Design principles</h2>
 * <ul>
 * <li><b>Single Responsibility</b>: this factory selects, resolvers
 * resolve</li>
 * <li><b>Explicit strategies</b>: all supported strategies are declared
 * via {@link RateLimitStrategy}</li>
 * <li><b>No runtime ambiguity</b>: exhaustive {@code switch} without
 * default branch</li>
 * <li><b>Fail-fast evolution</b>: adding a new strategy forces an explicit
 * decision at compile time</li>
 * </ul>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>No personally identifiable information (PII) is handled directly
 * by this factory</li>
 * <li>No dynamic or user-controlled strategy selection</li>
 * <li>Only production-approved strategies can be selected</li>
 * </ul>
 *
 * <h2>Operational context</h2>
 * <p>
 * The selected {@link RateLimitKeyResolver} is used by the
 * {@code LoginRateLimitingFilter} during early request processing,
 * before authentication is established.
 * </p>
 *
 * <p>
 * This design ensures deterministic behavior across clustered
 * and multi-instance deployments.
 * </p>
 */
@Component
public class RateLimitKeyResolverFactory {

    private final IpRateLimitKeyResolver ipResolver;
    private final IpUserRateLimitKeyResolver ipUserResolver;
    private final UserRateLimitKeyResolver userResolver;

    public RateLimitKeyResolverFactory(
            IpRateLimitKeyResolver ipResolver,
            IpUserRateLimitKeyResolver ipUserResolver,
            UserRateLimitKeyResolver userResolver) {

        this.ipResolver = ipResolver;
        this.ipUserResolver = ipUserResolver;
        this.userResolver = userResolver;
    }

    /**
     * Returns the {@link RateLimitKeyResolver} corresponding to the
     * configured {@link RateLimitStrategy}.
     *
     * <p>
     * This method is intentionally exhaustive: every supported strategy
     * must be explicitly mapped to a resolver.
     * </p>
     *
     * @param strategy configured rate-limiting strategy (never {@code null})
     * @return a production-safe {@link RateLimitKeyResolver} implementation
     */
    public RateLimitKeyResolver get(RateLimitStrategy strategy) {
        return switch (strategy) {
            case IP -> ipResolver;
            case USER -> userResolver;
            case IP_USER -> ipUserResolver;
        };
    }
}
