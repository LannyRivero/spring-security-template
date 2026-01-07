package com.lanny.spring_security_template.infrastructure.security.network;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Network security configuration bootstrap.
 */
@Configuration
@EnableConfigurationProperties(NetworkSecurityProperties.class)
public class NetworkSecurityConfig {
}
