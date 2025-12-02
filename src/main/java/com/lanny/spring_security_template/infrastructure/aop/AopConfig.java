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
public class AopConfig {
    // no additional beans required for now

}
