package com.lanny.spring_security_template.infrastructure.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lanny.spring_security_template.application.auth.policy.LoginAttemptPolicy;
import com.lanny.spring_security_template.infrastructure.config.RateLimitingProperties;
import com.lanny.spring_security_template.infrastructure.security.filter.LoginRateLimitingFilter;
import com.lanny.spring_security_template.infrastructure.security.handler.ApiErrorFactory;
import com.lanny.spring_security_template.infrastructure.security.ratelimit.RateLimitKeyResolver;
import com.lanny.spring_security_template.infrastructure.security.ratelimit.RateLimitKeyResolverFactory;

/**
 * ============================================================
 * LoginRateLimitingFilterConfig
 * ============================================================
 *
 * <p>
 * Spring configuration that registers the {@link LoginRateLimitingFilter}
 * responsible for protecting authentication endpoints against brute-force
 * and credential-stuffing attacks.
 * </p>
 *
 * <h2>Scope</h2>
 * <p>
 * This filter is expected to apply <b>only</b> to authentication-related
 * endpoints (e.g. login, token refresh). Endpoint restriction is enforced
 * internally by the filter itself.
 * </p>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>The rate-limiting strategy is defined by {@link LoginAttemptPolicy}</li>
 * <li>Rate-limit keys are resolved via {@link RateLimitKeyResolver}</li>
 * <li>Error responses are generated centrally via {@link ApiErrorFactory}</li>
 * </ul>
 *
 * <p>
 * This configuration contains no business logic and exists solely to wire
 * security components in a controlled and testable manner.
 * </p>
 */

@Configuration
public class LoginRateLimitingFilterConfig {

    /**
     * Creates the {@link LoginRateLimitingFilter} used to protect authentication
     * endpoints from excessive or abusive login attempts.
     */

    @Bean
    public LoginRateLimitingFilter loginRateLimitingFilter(
            RateLimitingProperties props,
            RateLimitKeyResolverFactory resolverFactory,
            ObjectMapper mapper,
            LoginAttemptPolicy loginAttemptPolicy,
            ApiErrorFactory apiErrorFactory) {

                RateLimitKeyResolver resolver =
                resolverFactory.get(props.strategy()); 
                        return new LoginRateLimitingFilter(
                props,
                resolver,
                mapper,
                loginAttemptPolicy,
                apiErrorFactory);
    }
}
