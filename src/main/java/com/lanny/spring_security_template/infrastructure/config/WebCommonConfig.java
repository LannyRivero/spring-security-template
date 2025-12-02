package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Registers all CORS-related configuration classes.
 *
 * <p>
 * This configuration does <b>not</b> apply CORS rules directly.
 * Instead, it exposes {@link SecurityCorsProperties} as a Spring bean so that
 * the CORS filter or MVC layer can consume it later.
 * </p>
 *
 * <p>
 * Keeping CORS configuration isolated avoids leaking infrastructure details
 * into controllers or security filters and supports clean layering.
 * </p>
 */
@Configuration
@EnableConfigurationProperties({ SecurityCorsProperties.class })
public class WebCommonConfig {
}
