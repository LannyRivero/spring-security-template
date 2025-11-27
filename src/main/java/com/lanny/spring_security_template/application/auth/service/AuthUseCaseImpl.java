package com.lanny.spring_security_template.application.auth.service;

import java.util.UUID;

import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.command.RegisterCommand;
import com.lanny.spring_security_template.application.auth.port.in.AuthUseCase;
import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;
import com.lanny.spring_security_template.application.auth.query.MeQuery;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.result.MeResult;
import com.lanny.spring_security_template.domain.event.SecurityEvent;
import com.lanny.spring_security_template.domain.time.ClockProvider;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Application-level facade for authentication use cases.
 *
 * <p>
 * Delegates the actual business logic to specialized services such as
 * {@link LoginService}, {@link RefreshService}, and {@link MeService}.
 * Ensures cross-cutting concerns like logging, trace correlation and
 * audit event publishing are applied consistently.
 * </p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthUseCaseImpl implements AuthUseCase {

    private final LoginService loginService;
    private final RefreshService refreshService;
    private final MeService meService;
    private final DevRegisterService devRegisterService;
    private final AuditEventPublisher auditEventPublisher;
    private final ClockProvider clockProvider;

    @Value("${spring.profiles.active:}")
    private String activeProfile;

    @Override
    public JwtResult login(LoginCommand cmd) {
        validateInput(cmd.username(), cmd.password());

        String traceId = UUID.randomUUID().toString();
        MDC.put("traceId", traceId);
        MDC.put("username", cmd.username());

        log.info("[AUTH_REQUEST] type=LOGIN user={} trace={}", cmd.username(), traceId);
        auditEventPublisher.publishAuthEvent(
                SecurityEvent.LOGIN_ATTEMPT.name(),
                cmd.username(),
                clockProvider.now(),
                "Login attempt initiated");

        try {
            JwtResult result = loginService.login(cmd);

            auditEventPublisher.publishAuthEvent(
                    SecurityEvent.LOGIN_SUCCESS.name(),
                    cmd.username(),
                    clockProvider.now(),
                    "User successfully authenticated");
            return result;

        } finally {
            MDC.clear();
        }
    }

    @Override
    public JwtResult refresh(RefreshCommand cmd) {
        String traceId = UUID.randomUUID().toString();
        MDC.put("traceId", traceId);
        log.info("[AUTH_REQUEST] type=REFRESH trace={}", traceId);

        try {
            JwtResult result = refreshService.refresh(cmd);
            auditEventPublisher.publishAuthEvent(
                    SecurityEvent.TOKEN_REFRESH.name(),
                    "anonymous",
                    clockProvider.now(),
                    "Token successfully refreshed");
            return result;
        } finally {
            MDC.clear();
        }
    }

    @Override
    public MeResult me(MeQuery query) {
        return meService.me(query.username());
    }

    @Override
    public void registerDev(RegisterCommand cmd) {
        if (!"dev".equalsIgnoreCase(activeProfile)) {
            throw new UnsupportedOperationException(
                    "Developer registration is only allowed in the 'dev' profile");
        }
        devRegisterService.register(cmd);
        log.info("[DEV_REGISTER] user={} created in DEV environment", cmd.username());
    }

    private void validateInput(String username, String password) {
        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            throw new IllegalArgumentException("Username and password must not be blank");
        }
        if (username.length() > 255 || password.length() > 255) {
            throw new IllegalArgumentException("Username or password too long");
        }
    }
}
