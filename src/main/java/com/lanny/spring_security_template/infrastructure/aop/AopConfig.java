package com.lanny.spring_security_template.infrastructure.aop;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

/**
 * Global AOP configuration for cross-cutting concerns.
 *
 * <p>
 * Enables proxy-based aspects to support infrastructure-level
 * cross-cutting concerns such as:
 * </p>
 * <ul>
 * <li>Use case logging</li>
 * <li>Metrics collection</li>
 * <li>Security auditing</li>
 * </ul>
 *
 * <p>
 * <strong>Scope (by design):</strong>
 * </p>
 * <ul>
 * <li>Application layer use cases only</li>
 * <li>No interception of domain layer</li>
 * <li>No interception of infrastructure adapters</li>
 * <li>No interception of web/controllers layer</li>
 * </ul>
 *
 * <p>
 * This explicit limitation is critical for predictability,
 * debuggability, and auditability in security-sensitive applications.
 * </p>
 */

@Configuration
@EnableAspectJAutoProxy(proxyTargetClass = true)
public class AopConfig {

}
