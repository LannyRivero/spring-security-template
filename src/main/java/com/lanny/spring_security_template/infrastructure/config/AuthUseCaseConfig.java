package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.lanny.spring_security_template.application.auth.port.in.AuthUseCase;
import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;
import com.lanny.spring_security_template.application.auth.service.*;
import com.lanny.spring_security_template.domain.time.ClockProvider;

@Configuration
public class AuthUseCaseConfig {

    @Bean
    AuthUseCase authUseCaseCore(
            LoginService loginService,
            RefreshService refreshService,
            MeService meService,
            DevRegisterService devRegisterService,
            ChangePasswordService changePasswordService) {

        return new AuthUseCaseImpl(
                loginService,
                refreshService,
                meService,
                devRegisterService,
                changePasswordService);
    }

    @Bean
    AuthUseCase authUseCase(AuthUseCase authUseCaseCore,
            AuditEventPublisher audit,
            ClockProvider clock) {

        return new AuthUseCaseLoggingDecorator(authUseCaseCore, audit, clock);
    }
}
