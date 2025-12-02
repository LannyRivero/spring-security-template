package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.lanny.spring_security_template.application.auth.port.in.AuthUseCase;
import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;
import com.lanny.spring_security_template.application.auth.service.AuthUseCaseImpl;
import com.lanny.spring_security_template.application.auth.service.AuthUseCaseLoggingDecorator;
import com.lanny.spring_security_template.application.auth.service.MeService;
import com.lanny.spring_security_template.domain.time.ClockProvider;
import com.lanny.spring_security_template.infrastructure.adapter.usecase.transactional.ChangePasswordTransactionalAdapter;
import com.lanny.spring_security_template.infrastructure.adapter.usecase.transactional.DevRegisterTransactionalAdapter;
import com.lanny.spring_security_template.infrastructure.adapter.usecase.transactional.LoginTransactionalAdapter;
import com.lanny.spring_security_template.infrastructure.adapter.usecase.transactional.RefreshTransactionalAdapter;

/**
 * ======================================================================
 * AuthUseCaseConfig
 * ======================================================================
 *
 * Infrastructure-level configuration responsible for assembling the
 * authentication application use case with:
 *
 * <ul>
 * <li>a pure core use case implementation ({@link AuthUseCaseImpl})</li>
 * <li>a decorator providing logging, auditing, and MDC propagation</li>
 * </ul>
 *
 * <h2>Architectural Role</h2>
 * <p>
 * This class acts as the composition root for authentication flows.
 * It ensures that the core business logic remains free of:
 * </p>
 *
 * <ul>
 * <li>infrastructure concerns</li>
 * <li>observability (logging/audit)</li>
 * <li>transaction management</li>
 * </ul>
 *
 * The decorator pattern is used to apply cross-cutting behaviour in a
 * controlled and testable manner.
 *
 * <h2>Clean Architecture Compliance</h2>
 * <ul>
 * <li>No Spring dependencies inside the core use case.</li>
 * <li>Decorators live in infrastructure and depend only on interfaces.</li>
 * <li>Composition happens exclusively in configuration.</li>
 * </ul>
 *
 * <h2>Security & Auditing</h2>
 * <p>
 * The decorated instance provides:
 * </p>
 * <ul>
 * <li>transaction boundaries (via adapters)</li>
 * <li>structured logging</li>
 * <li>audit event publication for login, refresh, password changes, etc.</li>
 * </ul>
 */
@Configuration
public class AuthUseCaseConfig {

    /**
     * Creates the pure, undecorated application use case.
     *
     * <p>
     * No logging, no auditing, no Spring-specific behaviour — just business
     * logic orchestrating the application services.
     * </p>
     */
    @Bean
    AuthUseCase authUseCaseCore(
            LoginTransactionalAdapter loginAdapter,
            RefreshTransactionalAdapter refreshAdapter,
            MeService meService,
            DevRegisterTransactionalAdapter devRegisterAdapter,
            ChangePasswordTransactionalAdapter changePasswordAdapter) {

        return new AuthUseCaseImpl(
                loginAdapter,
                refreshAdapter,
                meService,
                devRegisterAdapter,
                changePasswordAdapter);
    }

    /**
     * Decorated AuthUseCase adding:
     * <ul>
     * <li>structured logging</li>
     * <li>audit event publishing</li>
     * <li>MDC correlation propagation</li>
     * </ul>
     *
     * <p>
     * The decorator is the only version injected into controllers.
     * </p>
     */
    @Bean
    AuthUseCase authUseCase(
            AuthUseCase authUseCaseCore,
            AuditEventPublisher audit,
            ClockProvider clock) {

        return new AuthUseCaseLoggingDecorator(
                authUseCaseCore,
                audit,
                clock);
    }
}
