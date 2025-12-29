package com.lanny.spring_security_template.infrastructure.security;

import com.lanny.spring_security_template.application.auth.policy.LoginAttemptPolicy;
import com.lanny.spring_security_template.infrastructure.config.RateLimitingProperties;
import com.lanny.spring_security_template.infrastructure.security.filter.LoginRateLimitingFilter;
import com.lanny.spring_security_template.infrastructure.security.handler.ApiErrorFactory;
import com.lanny.spring_security_template.infrastructure.security.ratelimit.RateLimitKeyResolver;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class LoginRateLimitingFilterConfig {

    @Bean
    public LoginRateLimitingFilter loginRateLimitingFilter(
            RateLimitingProperties props,
            RateLimitKeyResolver keyResolver,
            ObjectMapper mapper,
            LoginAttemptPolicy loginAttemptPolicy,
            ApiErrorFactory apiErrorFactory) {
        return new LoginRateLimitingFilter(
                props,
                keyResolver,
                mapper,
                loginAttemptPolicy,
                apiErrorFactory);
    }
}
