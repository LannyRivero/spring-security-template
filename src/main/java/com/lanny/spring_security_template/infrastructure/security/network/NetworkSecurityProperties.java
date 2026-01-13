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
 * 
 * <h2> Scurity guarantees </h2>
 * <ul>
 *  <li>Only explicitly trusted proxy CIDR ranges are allowed</li>
 *  <li>Prevents X-Forwarded-For spoofing attacks</li>
 * </ul>
 */
@Validated
@ConfigurationProperties(prefix = "security.network")
public record NetworkSecurityProperties(

        /**
 * Trusted proxy IP range in CIDR notation.
         *
         * <p>
         * Examples:
         * <ul>
         * <li>10.0.0.0/8</li>
         * <li>192.168.0.0/16</li>
         * <li>172.16.0.0/12</li>
         * </ul>
         * </p>
         */
        @NotEmpty List<String> trustedProxyCidrs) {
}
