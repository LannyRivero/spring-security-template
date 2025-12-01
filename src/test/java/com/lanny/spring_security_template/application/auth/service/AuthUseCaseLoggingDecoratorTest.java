package com.lanny.spring_security_template.application.auth.service;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.MDC;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

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

@ExtendWith(OutputCaptureExtension.class)
class AuthUseCaseLoggingDecoratorTest {

    private AuthUseCase target;
    private AuditEventPublisher audit;
    private ClockProvider clock;

    private AuthUseCaseLoggingDecorator decorator;

    @BeforeEach
    void setUp() {
        target = mock(AuthUseCase.class);
        audit = mock(AuditEventPublisher.class);
        clock = mock(ClockProvider.class);

        when(clock.now()).thenReturn(Instant.parse("2024-01-01T10:00:00Z"));

        decorator = new AuthUseCaseLoggingDecorator(target, audit, clock);
    }

    // =====================================================================================
    @Test
    @DisplayName("LOGIN → Should log, audit and delegate when login succeeds")
    void testShouldLogAuditAndDelegateOnSuccessfulLogin(CapturedOutput output) {
        LoginCommand cmd = new LoginCommand("lanny", "pw123");
        JwtResult mockResult = new JwtResult("access", "refresh",
                Instant.parse("2030-01-01T00:00:00Z"));

        when(target.login(cmd)).thenReturn(mockResult);

        JwtResult result = decorator.login(cmd);

        assertThat(result).isEqualTo(mockResult);

        verify(audit).publishAuthEvent(
                eq(SecurityEvent.LOGIN_ATTEMPT.name()),
                eq("lanny"),
                any(),
                contains("Login attempt"));

        verify(audit).publishAuthEvent(
                eq(SecurityEvent.LOGIN_SUCCESS.name()),
                eq("lanny"),
                any(),
                anyString());

        assertThat(output).contains("AUTH_LOGIN_REQUEST");
        assertThat(output).contains("AUTH_LOGIN_SUCCESS");

        assertThat(MDC.get("traceId")).isNull();
        assertThat(MDC.get("username")).isNull();
    }

    // =====================================================================================
    @Test
    @DisplayName("LOGIN FAILURE → Should log and audit when login fails")
    void testShouldLogAuditAndPropagateExceptionOnLoginFailure(CapturedOutput output) {
        LoginCommand cmd = new LoginCommand("lanny", "pw123");

        when(target.login(cmd)).thenThrow(new RuntimeException("Invalid credentials"));

        assertThatThrownBy(() -> decorator.login(cmd))
                .isInstanceOf(RuntimeException.class);

        verify(audit).publishAuthEvent(
                eq(SecurityEvent.LOGIN_FAILURE.name()),
                eq("lanny"),
                any(),
                anyString());

        assertThat(output).contains("AUTH_LOGIN_FAILURE");
        assertThat(MDC.get("traceId")).isNull();
    }

    // =====================================================================================
    @Test
    @DisplayName("REFRESH → Should log, audit and delegate when refresh succeeds")
    void testShouldLogAuditAndDelegateOnSuccessfulRefresh(CapturedOutput output) {
        RefreshCommand cmd = new RefreshCommand("token123");
        JwtResult mockResult = new JwtResult("a", "r",
                Instant.parse("2030-01-01T00:00:00Z"));

        when(target.refresh(cmd)).thenReturn(mockResult);

        JwtResult result = decorator.refresh(cmd);

        assertThat(result).isEqualTo(mockResult);

        verify(audit).publishAuthEvent(
                eq(SecurityEvent.TOKEN_REFRESH_ATTEMPT.name()),
                eq("unknown"),
                any(),
                anyString());

        verify(audit).publishAuthEvent(
                eq(SecurityEvent.TOKEN_REFRESH.name()),
                eq("unknown"),
                any(),
                anyString());

        assertThat(output).contains("AUTH_REFRESH_SUCCESS");

        assertThat(MDC.get("traceId")).isNull();
        assertThat(MDC.get("operation")).isNull();
    }

    // =====================================================================================
    @Test
    @DisplayName("REFRESH FAILURE → Should log and audit when refresh fails")
    void testShouldLogAuditAndPropagateExceptionOnRefreshFailure(CapturedOutput output) {
        RefreshCommand cmd = new RefreshCommand("invalid");

        when(target.refresh(cmd)).thenThrow(new RuntimeException("Expired token"));

        assertThatThrownBy(() -> decorator.refresh(cmd))
                .isInstanceOf(RuntimeException.class);

        verify(audit).publishAuthEvent(
                eq(SecurityEvent.TOKEN_REFRESH_FAILED.name()),
                eq("unknown"),
                any(),
                any());

        assertThat(output).contains("AUTH_REFRESH_FAILURE");
    }

    // =====================================================================================
    @Test
    @DisplayName("CHANGE PASSWORD → Should log, audit and delegate")
    void testShouldLogAuditAndDelegateOnChangePassword(CapturedOutput output) {
        decorator.changePassword("lanny", "old", "new");

        verify(target).changePassword("lanny", "old", "new");

        verify(audit).publishAuthEvent(eq(SecurityEvent.PASSWORD_CHANGE_ATTEMPT.name()), eq("lanny"), any(), any());
        verify(audit).publishAuthEvent(eq(SecurityEvent.PASSWORD_CHANGED.name()), eq("lanny"), any(), any());

        assertThat(output).contains("AUTH_CHANGE_PASSWORD_SUCCESS");

        assertThat(MDC.get("username")).isNull();
    }

    // =====================================================================================
    @Test
    @DisplayName("CHANGE PASSWORD FAILURE → Should log and audit failure")
    void testShouldLogAuditAndPropagateExceptionOnPasswordChangeFailure(CapturedOutput output) {
        doThrow(new RuntimeException("wrong pwd"))
                .when(target).changePassword("lanny", "old", "new");

        assertThatThrownBy(() -> decorator.changePassword("lanny", "old", "new"))
                .isInstanceOf(RuntimeException.class);

        verify(audit).publishAuthEvent(eq(SecurityEvent.PASSWORD_CHANGE_FAILED.name()), eq("lanny"), any(), any());

        assertThat(output).contains("AUTH_CHANGE_PASSWORD_FAILURE");
    }

    // =====================================================================================
    @Test
    @DisplayName("ME → Should log and delegate identity lookup")
    void testShouldDelegateMeQuery() {
        MeQuery query = new MeQuery("lanny");
        MeResult mockResult = new MeResult("lanny", "qw", List.of(), List.of());

        when(target.me(query)).thenReturn(mockResult);

        MeResult result = decorator.me(query);

        assertThat(result).isEqualTo(mockResult);
    }

    // =====================================================================================
    @Test
    @DisplayName("REGISTER DEV → Should log and delegate developer registration")
    void testShouldLogAndDelegateDevRegistration() {
        RegisterCommand cmd = new RegisterCommand("x", "y", "z@z.com", List.of("ROLE_USER"), List.of());

        decorator.registerDev(cmd);

        verify(target).registerDev(cmd);
    }
}
