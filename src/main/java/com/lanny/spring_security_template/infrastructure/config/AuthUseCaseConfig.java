package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

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
 * AuthUseCaseConfig (Enterprise Version)
 * ======================================================================
 *
 * Infrastructure-level composition root for the authentication workflow.
 *
 * This configuration wires:
 * - the pure core UseCase (AuthUseCaseImpl)
 * - a decorator adding logging, auditing and MDC correlation
 *
 * Clean Architecture Compliance:
 * - Core has no Spring, no logging, no auditing.
 * - All cross-cutting concerns live in Infrastructure.
 * - Controllers ONLY see the decorated version (@Primary).
 */
@Configuration
public class AuthUseCaseConfig {

    /**
     * ------------------------------------------------------------------
     * CORE USE CASE (no logging, no Spring, no auditing)
     * ------------------------------------------------------------------
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
     * ------------------------------------------------------------------
     * DECORATED USE CASE (logging + auditing + MDC)
     * ------------------------------------------------------------------
     *
     * This is the version injected everywhere. It wraps the core with
     * structured audit logging, correlation IDs and timestamp tracking.
     */
    @Bean
    @Primary
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
