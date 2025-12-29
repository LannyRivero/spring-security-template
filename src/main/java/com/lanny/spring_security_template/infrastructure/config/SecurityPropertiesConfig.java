package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@Configuration
@Profile("!test")
@EnableConfigurationProperties({
        SecurityJwtProperties.class,
        RateLimitingProperties.class
})
public class SecurityPropertiesConfig {
}
