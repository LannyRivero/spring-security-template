package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties({ SecurityCorsProperties.class })
public class WebCommonConfig {
}
