package com.lanny.spring_security_template.infrastructure.config;

import java.time.Duration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.lanny.spring_security_template.application.auth.policy.RefreshTokenPolicy;
import com.lanny.spring_security_template.application.auth.policy.RotationPolicy;
import com.lanny.spring_security_template.application.auth.policy.SessionPolicy;
import com.lanny.spring_security_template.application.auth.policy.TokenPolicyProperties;

@Configuration
public class AuthPolicyConfig {

    @Bean
    TokenPolicyProperties tokenPolicyProperties(SecurityJwtProperties props) {
        return new TokenPolicyProperties() {
            @Override
            public Duration accessTokenTtl() {
                return props.accessTtl();
            }

            @Override
            public Duration refreshTokenTtl() {
                return props.refreshTtl();
            }

            @Override
            public String issuer() {
                return props.issuer();
            }

            @Override
            public String accessAudience() {
                return props.accessAudience();
            }

            @Override
            public String refreshAudience() {
                return props.refreshAudience();
            }
        };
    }

    @Bean
    RefreshTokenPolicy refreshTokenPolicy(SecurityJwtProperties props) {
        return props::refreshAudience;
    }

    @Bean
    SessionPolicy sessionPolicy(SecurityJwtProperties props) {
        return props::maxActiveSessions;
    }

    @Bean
    RotationPolicy rotationPolicy(SecurityJwtProperties props) {
        return props::rotateRefreshTokens;
    }
}
