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

@ExtendWith(MockitoExtension.class)
class AuthUseCaseImplTest {

    @Mock
    private LoginService loginService;
    @Mock
    private RefreshService refreshService;
    @Mock
    private MeService meService;
    @Mock
    private DevRegisterService devRegisterService;

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
    @DisplayName(" login() → should delegate to LoginService and return JwtResult")
    void testShouldReturnJwtResultWhenLoginCommandIsValid() {
        LoginCommand cmd = new LoginCommand("lanny", "1234");
        when(loginService.login(cmd)).thenReturn(jwtResult);

        JwtResult result = authUseCase.login(cmd);

        verify(loginService).login(cmd);
        verifyNoInteractions(refreshService, meService, devRegisterService);
        assertThat(result.accessToken()).isEqualTo("ACCESS_TOKEN");
    }

    @Test
    @DisplayName(" login() → should propagate exception when LoginService fails")
    void testShouldPropagateExceptionWhenLoginFails() {
        LoginCommand cmd = new LoginCommand("lanny", "wrong");
        when(loginService.login(cmd)).thenThrow(new RuntimeException("Invalid credentials"));

        assertThatThrownBy(() -> authUseCase.login(cmd))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Invalid credentials");

        verify(loginService).login(cmd);
    }

    // -----------------------------------------------------------
    // REFRESH
    // -----------------------------------------------------------
    @Test
    @DisplayName(" refresh() → should return JwtResult when RefreshCommand valid")
    void testShouldReturnJwtResultWhenRefreshCommandValid() {
        RefreshCommand cmd = new RefreshCommand("REFRESH_ABC123");
        when(refreshService.refresh(cmd)).thenReturn(jwtResult);

        JwtResult result = authUseCase.refresh(cmd);

        verify(refreshService).refresh(cmd);
        verifyNoInteractions(loginService, meService, devRegisterService);
        assertThat(result.refreshToken()).isEqualTo("REFRESH_TOKEN");
    }

    @Test
    @DisplayName(" refresh() → should propagate exception when RefreshToken invalid")
    void testShouldPropagateExceptionWhenRefreshTokenInvalid() {
        RefreshCommand cmd = new RefreshCommand("INVALID_REFRESH");
        when(refreshService.refresh(cmd)).thenThrow(new IllegalArgumentException("Invalid refresh token"));

        assertThatThrownBy(() -> authUseCase.refresh(cmd))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid refresh token");

        verify(refreshService).refresh(cmd);
    }

    // -----------------------------------------------------------
    // ME
    // -----------------------------------------------------------
    @Test
    @DisplayName(" me() → should return MeResult when user exists")
    void testShouldReturnMeResultWhenUserExists() {
        MeQuery query = new MeQuery("lanny");
        when(meService.me("lanny")).thenReturn(meResult);

        MeResult result = authUseCase.me(query);

        verify(meService).me("lanny");
        verifyNoInteractions(loginService, refreshService, devRegisterService);
        assertThat(result.username()).isEqualTo("lanny");
        assertThat(result.roles()).containsExactly("ADMIN");
    }

    @Test
    @DisplayName(" me() → should propagate exception when user not found")
    void testShouldPropagateExceptionWhenUserNotFound() {
        MeQuery query = new MeQuery("ghost");
        when(meService.me("ghost")).thenThrow(new IllegalArgumentException("User not found"));

        assertThatThrownBy(() -> authUseCase.me(query))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("User not found");

        verify(meService).me("ghost");
    }

    // -----------------------------------------------------------
    // REGISTER DEV
    // -----------------------------------------------------------
    @Test
    @DisplayName(" registerDev() → should call DevRegisterService successfully")
    void testShouldInvokeDevRegisterServiceWhenCommandValid() {
        RegisterCommand cmd = new RegisterCommand(
                "newUser",
                "new@user.com",
                "123456",
                List.of("ADMIN"),
                List.of("scope:all"));

        authUseCase.registerDev(cmd);

        verify(devRegisterService).register(cmd);
        verifyNoInteractions(loginService, refreshService, meService);
    }

    @Test
    @DisplayName(" registerDev() → should propagate exception when service fails")
    void testShouldPropagateExceptionWhenRegisterDevFails() {
        RegisterCommand cmd = new RegisterCommand("dupUser", "dup@mail.com", "pass", List.of(), List.of());
        doThrow(new IllegalStateException("User already exists")).when(devRegisterService).register(cmd);

        assertThatThrownBy(() -> authUseCase.registerDev(cmd))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("User already exists");

        verify(devRegisterService).register(cmd);
    }

    // -----------------------------------------------------------
    // INDEPENDENCE CHECK
    // -----------------------------------------------------------
    @Test
    @DisplayName(" should ensure all methods are independent (no cross-service calls)")
    void testShouldKeepServicesIndependentBetweenUseCaseMethods() {
        LoginCommand loginCmd = new LoginCommand("a", "b");
        RefreshCommand refreshCmd = new RefreshCommand("t");
        MeQuery meQuery = new MeQuery("u");
        RegisterCommand regCmd = new RegisterCommand("n", "e", "p", List.of(), List.of());

        when(loginService.login(loginCmd)).thenReturn(jwtResult);
        when(refreshService.refresh(refreshCmd)).thenReturn(jwtResult);
        when(meService.me("u")).thenReturn(meResult);

        authUseCase.login(loginCmd);
        authUseCase.refresh(refreshCmd);
        authUseCase.me(meQuery);
        authUseCase.registerDev(regCmd);

        verify(loginService).login(loginCmd);
        verify(refreshService).refresh(refreshCmd);
        verify(meService).me("u");
        verify(devRegisterService).register(regCmd);
        verifyNoMoreInteractions(loginService, refreshService, meService, devRegisterService);
    }
}
