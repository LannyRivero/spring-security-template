package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.lanny.spring_security_template.application.auth.port.in.AuthUseCase;
import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;
import com.lanny.spring_security_template.application.auth.service.*;
import com.lanny.spring_security_template.domain.time.ClockProvider;
import com.lanny.spring_security_template.infrastructure.adapter.usecase.ChangePasswordTransactionalAdapter;
import com.lanny.spring_security_template.infrastructure.adapter.usecase.DevRegisterTransactionalAdapter;

@Configuration
public class AuthUseCaseConfig {

    /*
     * ============================================================
     * CORE USE CASE
     * ============================================================
     */
    @Bean
    AuthUseCase authUseCaseCore(
            LoginService loginService,
            RefreshService refreshService,
            MeService meService,
            DevRegisterTransactionalAdapter devRegisterAdapter,
            ChangePasswordTransactionalAdapter changePasswordAdapter) {

        return new AuthUseCaseImpl(
                loginService,
                refreshService,
                meService,
                devRegisterAdapter,
                changePasswordAdapter);
    }

    /*
     * ============================================================
     * DECORATED USE CASE
     * ============================================================
     */
    @Bean
    AuthUseCase authUseCase(
            AuthUseCase authUseCaseCore,
            AuditEventPublisher audit,
            ClockProvider clock) {
        return new AuthUseCaseLoggingDecorator(authUseCaseCore, audit, clock);
    }
}
