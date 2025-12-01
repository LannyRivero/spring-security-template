package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.lanny.spring_security_template.application.auth.port.in.AuthUseCase;
import com.lanny.spring_security_template.application.auth.service.AuthUseCaseImpl;
import com.lanny.spring_security_template.application.auth.service.*;
import com.lanny.spring_security_template.infrastructure.adapter.usecase.*;
import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;
import com.lanny.spring_security_template.domain.time.ClockProvider;

@Configuration
public class AuthUseCaseConfig {

    /*
     * ============================================================
     * CORE USE CASE (NO SPRING, NO LOGGING, NO TRANSACTIONS)
     * ============================================================
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

    /*
     * ============================================================
     * DECORATED USE CASE (Logging + Audit + MDC)
     * ============================================================
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
