package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.domain.valueobject.Username;
import com.lanny.spring_security_template.infrastructure.metrics.AuthMetricsServiceImpl;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LoginServiceTest {

    @Mock
    private UserAccountGateway userAccountGateway;
    @Mock
    private PasswordHasher passwordHasher;
    @Mock
    private RoleProvider roleProvider;
    @Mock
    private ScopePolicy scopePolicy;
    @Mock
    private TokenIssuer tokenIssuer;
    @Mock
    private SessionManager sessionManager;
    @Mock
    private RefreshTokenStore refreshTokenStore;
    @Mock
    private AuthMetricsServiceImpl metrics;

    @InjectMocks
    private LoginService loginService;

    private LoginCommand command;
    private IssuedTokens issuedTokens;
    private JwtResult jwtResult;

    @BeforeEach
    void setUp() {
        command = new LoginCommand("lanny", "pass123");

        issuedTokens = new IssuedTokens(
                "lanny",
                "ACCESS_TOKEN",
                "REFRESH_TOKEN",
                "JTI-1",
                Instant.now(),
                Instant.now().plusSeconds(600),
                Instant.now().plusSeconds(3600),
                List.of("ADMIN"),
                List.of("profile:read"));

        jwtResult = issuedTokens.toJwtResult();
    }

    //  HAPPY PATH
    @Test
    @DisplayName(" should complete login successfully and return JwtResult")
    void testShouldReturnJwtResultWhenCredentialsValid() {
        User user = mock(User.class);
        lenient().when(user.username()).thenReturn(Username.of("lanny"));

        when(userAccountGateway.findByUsernameOrEmail("lanny"))
                .thenReturn(Optional.of(user));

        doNothing().when(user).ensureCanAuthenticate();
        doNothing().when(user).verifyPassword("pass123", passwordHasher);

        RoleScopeResult rs = new RoleScopeResult(
                List.of("ADMIN"),
                List.of("profile:read"));

        try (MockedStatic<RoleScopeResolver> mocked = mockStatic(RoleScopeResolver.class)) {
            mocked.when(() -> RoleScopeResolver.resolve("lanny", roleProvider, scopePolicy))
                    .thenReturn(rs);

            when(tokenIssuer.issueTokens("lanny", rs)).thenReturn(issuedTokens);

            JwtResult result = loginService.login(command);

            assertThat(result.accessToken()).isEqualTo("ACCESS_TOKEN");
            assertThat(result.refreshToken()).isEqualTo("REFRESH_TOKEN");

            verify(userAccountGateway).findByUsernameOrEmail("lanny");
            verify(user).ensureCanAuthenticate();
            verify(user).verifyPassword("pass123", passwordHasher);
            verify(refreshTokenStore).save(eq("lanny"), eq("JTI-1"), any(), any());
            verify(sessionManager).register(issuedTokens);
            verify(metrics).recordLoginSuccess();
        }
    }

    //  USER NOT FOUND
    @Test
    @DisplayName(" should throw UsernameNotFoundException when user not found")
    void testShouldThrowWhenUserNotFound() {
        when(userAccountGateway.findByUsernameOrEmail("ghost"))
                .thenReturn(Optional.empty());

        LoginCommand cmd = new LoginCommand("ghost", "pwd");

        assertThatThrownBy(() -> loginService.login(cmd))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("ghost");

        verify(metrics, never()).recordLoginSuccess();
        verify(metrics, never()).recordLoginFailure();
    }

    //  USER LOCKED
    @Test
    @DisplayName(" should propagate exception when user cannot authenticate")
    void testShouldPropagateWhenUserCannotAuthenticate() {
        User user = mock(User.class);
        when(userAccountGateway.findByUsernameOrEmail("lanny"))
                .thenReturn(Optional.of(user));

        doThrow(new IllegalStateException("User locked"))
                .when(user).ensureCanAuthenticate();

        assertThatThrownBy(() -> loginService.login(command))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("locked");

        verify(metrics, never()).recordLoginSuccess();
        verify(metrics, never()).recordLoginFailure();
    }

    //  INVALID PASSWORD
    @Test
    @DisplayName(" should record failure and throw InvalidCredentialsException when password invalid")
    void testShouldRecordFailureWhenPasswordInvalid() {
        User user = mock(User.class);
        lenient().when(user.username()).thenReturn(Username.of("lanny"));
        when(userAccountGateway.findByUsernameOrEmail("lanny"))
                .thenReturn(Optional.of(user));

        doNothing().when(user).ensureCanAuthenticate();
        doThrow(new InvalidCredentialsException("bad pass"))
                .when(user).verifyPassword("pass123", passwordHasher);

        assertThatThrownBy(() -> loginService.login(command))
                .isInstanceOf(InvalidCredentialsException.class)
                .hasMessageContaining("Invalid username or password");

        verify(metrics).recordLoginFailure();
        verify(metrics, never()).recordLoginSuccess();
        verifyNoInteractions(refreshTokenStore, sessionManager);
    }

    //  REFRESH & SESSION
    @Test
    @DisplayName(" should save refresh token and register session")
    void testShouldSaveRefreshTokenAndRegisterSession() {
        User user = mock(User.class);
        when(user.username()).thenReturn(Username.of("lanny"));
        when(userAccountGateway.findByUsernameOrEmail("lanny"))
                .thenReturn(Optional.of(user));

        doNothing().when(user).ensureCanAuthenticate();
        doNothing().when(user).verifyPassword("pass123", passwordHasher);

        RoleScopeResult rs = new RoleScopeResult(
                List.of("ADMIN"),
                List.of("scope:all"));

        try (MockedStatic<RoleScopeResolver> mocked = mockStatic(RoleScopeResolver.class)) {
            mocked.when(() -> RoleScopeResolver.resolve("lanny", roleProvider, scopePolicy))
                    .thenReturn(rs);

            when(tokenIssuer.issueTokens("lanny", rs)).thenReturn(issuedTokens);

            loginService.login(command);

            verify(refreshTokenStore).save("lanny", "JTI-1", issuedTokens.issuedAt(), issuedTokens.refreshExp());
            verify(sessionManager).register(issuedTokens);
        }
    }
}
