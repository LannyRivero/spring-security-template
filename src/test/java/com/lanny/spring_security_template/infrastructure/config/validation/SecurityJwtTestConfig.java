package com.lanny.spring_security_template.infrastructure.config.validation;

import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(SecurityJwtProperties.class)
public class SecurityJwtTestConfig {

    @Bean
    SecurityJwtPropertiesValidator validator(SecurityJwtProperties props) {
        return new SecurityJwtPropertiesValidator();
    }
}
