package com.lanny.spring_security_template.infrastructure.security.network;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotEmpty;

/**
 * Network security configuration.
 *
 * <p>
 * Defines trusted proxy IP ranges allowed to influence
 * client IP resolution (e.g. load balancers, gateways).
 * </p>
 */
@Validated
@ConfigurationProperties(prefix = "security.network")
public record NetworkSecurityProperties(

        /**
         * Trusted proxy IP prefixes.
         *
         * <p>
         * Examples:
         * <ul>
         * <li>10.</li>
         * <li>192.168.</li>
         * <li>172.16.</li>
         * </ul>
         * </p>
         */
        @NotEmpty List<String> trustedProxyPrefixes) {
}
