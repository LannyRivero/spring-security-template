package com.lanny.spring_security_template.application.auth.service;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.command.RegisterCommand;
import com.lanny.spring_security_template.application.auth.query.MeQuery;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.result.MeResult;
import com.lanny.spring_security_template.infrastructure.adapter.usecase.ChangePasswordTransactionalAdapter;
import com.lanny.spring_security_template.infrastructure.adapter.usecase.DevRegisterTransactionalAdapter;
import com.lanny.spring_security_template.infrastructure.adapter.usecase.LoginTransactionalAdapter;
import com.lanny.spring_security_template.infrastructure.adapter.usecase.RefreshTransactionalAdapter;

@ExtendWith(MockitoExtension.class)
class AuthUseCaseImplTest {

    @Mock private LoginTransactionalAdapter loginAdapter;
    @Mock private RefreshTransactionalAdapter refreshAdapter;
    @Mock private MeService meService;
    @Mock private DevRegisterTransactionalAdapter devRegisterAdapter;
    @Mock private ChangePasswordTransactionalAdapter changePasswordAdapter;

    @InjectMocks
    private AuthUseCaseImpl authUseCase;

    private JwtResult jwtResult;
    private MeResult meResult;

    @BeforeEach
    void setUp() {
        jwtResult = new JwtResult("ACCESS_TOKEN", "REFRESH_TOKEN", Instant.now().plusSeconds(600));
        meResult = new MeResult("user-1", "lanny", List.of("ADMIN"), List.of("profile:read"));
    }

    // -----------------------------------------------------------
    // LOGIN
    // -----------------------------------------------------------
    @Test
    @DisplayName("login() → delegates to LoginTransactionalAdapter and returns JwtResult")
    void testShouldLoginDelegation() {
        LoginCommand cmd = new LoginCommand("lanny", "1234");
        when(loginAdapter.login(cmd)).thenReturn(jwtResult);

        JwtResult result = authUseCase.login(cmd);

        verify(loginAdapter).login(cmd);
        assertThat(result.accessToken()).isEqualTo("ACCESS_TOKEN");
    }

    @Test
    @DisplayName("login() → should validate input and propagate exception")
    void testShouldLoginValidationFailure() {
        LoginCommand cmd = new LoginCommand("", "1234");

        assertThatThrownBy(() -> authUseCase.login(cmd))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("blank");
    }

    // -----------------------------------------------------------
    // REFRESH
    // -----------------------------------------------------------
    @Test
    @DisplayName("refresh() → delegates to RefreshTransactionalAdapter")
    void testShouldRefreshDelegation() {
        RefreshCommand cmd = new RefreshCommand("REFRESH_123");
        when(refreshAdapter.refresh(cmd)).thenReturn(jwtResult);

        JwtResult result = authUseCase.refresh(cmd);

        verify(refreshAdapter).refresh(cmd);
        assertThat(result.refreshToken()).isEqualTo("REFRESH_TOKEN");
    }

    // -----------------------------------------------------------
    // ME
    // -----------------------------------------------------------
    @Test
    @DisplayName("me() → returns MeResult via MeService")
    void testShouldMe() {
        MeQuery query = new MeQuery("lanny");
        when(meService.me("lanny")).thenReturn(meResult);

        MeResult result = authUseCase.me(query);

        verify(meService).me("lanny");
        assertThat(result.username()).isEqualTo("lanny");
    }

    // -----------------------------------------------------------
    // REGISTER DEV
    // -----------------------------------------------------------
    @Test
    @DisplayName("registerDev() → delegates to DevRegisterTransactionalAdapter")
    void testShouldRegisterDev() {
        RegisterCommand cmd = new RegisterCommand(
                "newUser", "mail@test.com", "1234",
                List.of("ADMIN"), List.of("scope:all"));

        authUseCase.registerDev(cmd);

        verify(devRegisterAdapter).register(cmd);
    }

    // -----------------------------------------------------------
    // CHANGE PASSWORD
    // -----------------------------------------------------------
    @Test
    @DisplayName("changePassword() → delegates to ChangePasswordTransactionalAdapter")
    void testShouldChangePassword() {
        authUseCase.changePassword("user", "old", "new");

        verify(changePasswordAdapter).changePassword("user", "old", "new");
    }
}

