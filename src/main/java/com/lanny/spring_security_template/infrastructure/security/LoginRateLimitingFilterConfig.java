package com.lanny.spring_security_template.infrastructure.security;

import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;
import com.lanny.spring_security_template.domain.time.ClockProvider;
import com.lanny.spring_security_template.infrastructure.config.RateLimitingProperties;
import com.lanny.spring_security_template.infrastructure.security.filter.LoginRateLimitingFilter;
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
            AuthMetricsService metrics,
            ClockProvider clockProvider
    ) {
        return new LoginRateLimitingFilter(
                props,
                keyResolver,
                mapper,
                metrics,
                clockProvider
        );
    }
}

