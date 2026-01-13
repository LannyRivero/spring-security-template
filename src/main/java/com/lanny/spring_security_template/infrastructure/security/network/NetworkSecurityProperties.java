package com.lanny.spring_security_template.infrastructure.security.network;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotEmpty;

/**
 * ============================================================
 * NetworkSecurityProperties
 * ============================================================
 *
 * <p>
 * Immutable configuration properties defining the set of trusted
 * proxy IP ranges allowed to influence client IP resolution.
 * </p>
 *
 * <p>
 * These properties are consumed during the security bootstrap phase
 * and are considered part of the application's trust boundary.
 * </p>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>Only explicitly trusted proxy CIDR ranges are honored</li>
 * <li>Prevents {@code X-Forwarded-For} spoofing from untrusted sources</li>
 * <li>Fail-fast validation at application startup</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>This class contains no runtime logic</li>
 * <li>Semantic validation is enforced by bootstrap guards</li>
 * <li>Supports both IPv4 and IPv6 CIDR notation</li>
 * </ul>
 *
 * @see ClientIpResolver
 * @see NetworkSecurityConfig
 * @see com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.guard.NetworkSecurityProdGuard
 */
@Validated
@ConfigurationProperties(prefix = "security.network")
public record NetworkSecurityProperties(

                /**
                 * List of trusted proxy IP ranges expressed in CIDR notation.
                 *
                 * <p>
                 * Only requests originating from these ranges are allowed to
                 * influence client IP resolution via forwarding headers.
                 * </p>
                 *
                 * <h3>Examples</h3>
                 * <ul>
                 * <li>{@code 10.0.0.0/8}</li>
                 * <li>{@code 192.168.0.0/16}</li>
                 * <li>{@code 172.16.0.0/12}</li>
                 * <li>{@code fd00::/8} (IPv6)</li>
                 * </ul>
                 */
                @NotEmpty List<String> trustedProxyCidrs) {
}
