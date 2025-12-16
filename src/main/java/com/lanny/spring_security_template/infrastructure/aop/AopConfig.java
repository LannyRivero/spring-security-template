package com.lanny.spring_security_template.infrastructure.aop;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

/**
 * Global AOP configuration.
 * 
 * Enable proxy-based aspects fot cross-cutting concerns:
 * -use-case logging
 * -metrics
 * -security auditing
 */
@Configuration
@EnableAspectJAutoProxy(proxyTargetClass = true)

/**
 * AOP configuration for cros-cutting concerns;
 * 
 * Scope(by desing):
 * -Application layer use cases(logging, metrics, audit)
 * -No interception of:
 * -Domain layer
 * -Infrastructure adapters
 * -Controllers
 * 
 * This explicit limitation is critical for predictability
 * and auditability in security-sensitive applications.
 */
public class AopConfig {

}
