package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.port.out.*;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import com.lanny.spring_security_template.domain.time.ClockProvider;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.metrics.AuthMetricsServiceImpl;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Professional-level test class for {@link RefreshService}.
 * 
 * Each test declares only what it truly needs (no unnecessary stubbing).
 */
@ExtendWith(MockitoExtension.class)
class RefreshServiceTest {

    @Mock
    private TokenProvider tokenProvider;
    @Mock
    private RoleProvider roleProvider;
    @Mock
    private ScopePolicy scopePolicy;
    @Mock
    private RefreshTokenStore refreshTokenStore;
    @Mock
    private SessionRegistryGateway sessionRegistry;
    @Mock
    private TokenBlacklistGateway blacklist;
    @Mock
    private SecurityJwtProperties props;
    @Mock
    private ClockProvider clockProvider;
    @Mock
    private TokenIssuer tokenIssuer;
    @Mock
    private AuthMetricsServiceImpl metrics;

    @InjectMocks
    private RefreshService refreshService;

    private static final String REFRESH_TOKEN = "valid-refresh-token";
    private static final String NEW_ACCESS_TOKEN = "new-access-token";
    private static final String USERNAME = "lanny";
    private static final String REFRESH_JTI = "refresh-1234";
    private final Instant now = Instant.parse("2025-01-01T00:00:00Z");
    private final Duration accessTtl = Duration.ofMinutes(15);

    private MockedStatic<RoleScopeResolver> roleScopeResolverMock;

    @BeforeEach
    void init() {
        roleScopeResolverMock = Mockito.mockStatic(RoleScopeResolver.class);
    }

    @AfterEach
    void tearDown() {
        if (roleScopeResolverMock != null)
            roleScopeResolverMock.close();
    }

    @Test
    @DisplayName(" should complete token refresh with rotation enabled")
    void testShouldRefreshWithRotationEnabled() {
        RefreshCommand cmd = new RefreshCommand(REFRESH_TOKEN);

        JwtClaimsDTO claims = new JwtClaimsDTO(
                USERNAME, REFRESH_JTI, List.of("refresh_audience"),
                now.getEpochSecond(), now.getEpochSecond(),
                now.plusSeconds(3600).getEpochSecond(),
                List.of("ROLE_USER"), List.of("profile:read"));

        // Arrange
        when(tokenProvider.validateAndGetClaims(REFRESH_TOKEN)).thenReturn(Optional.of(claims));
        when(refreshTokenStore.exists(REFRESH_JTI)).thenReturn(true);
        when(blacklist.isRevoked(REFRESH_JTI)).thenReturn(false);
        when(props.rotateRefreshTokens()).thenReturn(true);
        when(props.refreshAudience()).thenReturn("refresh_audience");
        when(props.accessTtl()).thenReturn(accessTtl);
        when(clockProvider.now()).thenReturn(now);

        IssuedTokens issued = new IssuedTokens(
                USERNAME, NEW_ACCESS_TOKEN, "new-refresh", "new-jti",
                now, now.plus(accessTtl), now.plus(Duration.ofHours(1)),
                List.of("ROLE_USER"), List.of("profile:read"));

        RoleScopeResult rs = new RoleScopeResult(issued.roleNames(), issued.scopeNames());
        roleScopeResolverMock.when(() -> RoleScopeResolver.resolve(USERNAME, roleProvider, scopePolicy)).thenReturn(rs);
        when(tokenIssuer.issueTokens(USERNAME, rs)).thenReturn(issued);

        // Act
        JwtResult result = refreshService.refresh(cmd);

        // Assert
        assertThat(result.accessToken()).isEqualTo(NEW_ACCESS_TOKEN);
        assertThat(result.refreshToken()).isEqualTo("new-refresh");
        verify(blacklist).revoke(eq(REFRESH_JTI), any());
        verify(refreshTokenStore).delete(REFRESH_JTI);
        verify(sessionRegistry).removeSession(USERNAME, REFRESH_JTI);
        verify(refreshTokenStore).save(eq(USERNAME), eq("new-jti"), any(), any());
        verify(sessionRegistry).registerSession(eq(USERNAME), eq("new-jti"), any());
        verify(metrics).recordTokenRefresh();
    }

    @Test
    @DisplayName(" should generate new access token without rotation")
    void testShouldRefreshWithoutRotation() {
        RefreshCommand cmd = new RefreshCommand(REFRESH_TOKEN);

        JwtClaimsDTO claims = new JwtClaimsDTO(
                USERNAME, REFRESH_JTI, List.of("refresh_audience"),
                now.getEpochSecond(), now.getEpochSecond(),
                now.plusSeconds(3600).getEpochSecond(),
                List.of("ROLE_USER"), List.of("profile:read"));

        // Arrange
        when(tokenProvider.validateAndGetClaims(REFRESH_TOKEN)).thenReturn(Optional.of(claims));
        when(refreshTokenStore.exists(REFRESH_JTI)).thenReturn(true);
        when(blacklist.isRevoked(REFRESH_JTI)).thenReturn(false);
        when(props.rotateRefreshTokens()).thenReturn(false);
        when(props.refreshAudience()).thenReturn("refresh_audience");
        when(props.accessTtl()).thenReturn(accessTtl);
        when(clockProvider.now()).thenReturn(now);

        RoleScopeResult rs = new RoleScopeResult(List.of("ROLE_USER"), List.of("profile:read"));
        roleScopeResolverMock.when(() -> RoleScopeResolver.resolve(USERNAME, roleProvider, scopePolicy)).thenReturn(rs);

        when(tokenProvider.generateAccessToken(USERNAME, rs.roleNames(), rs.scopeNames(), accessTtl))
                .thenReturn(NEW_ACCESS_TOKEN);

        // Act
        JwtResult result = refreshService.refresh(cmd);

        // Assert
        assertThat(result.accessToken()).isEqualTo(NEW_ACCESS_TOKEN);
        assertThat(result.refreshToken()).isEqualTo(REFRESH_TOKEN);
        verify(tokenProvider).generateAccessToken(USERNAME, rs.roleNames(), rs.scopeNames(), accessTtl);
        verifyNoInteractions(tokenIssuer);
    }

    @Test
    @DisplayName(" should throw when validateAndGetClaims returns empty (invalid token)")
    void testShouldThrowWhenInvalidToken() {
        RefreshCommand cmd = new RefreshCommand(REFRESH_TOKEN);
        when(tokenProvider.validateAndGetClaims(REFRESH_TOKEN)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> refreshService.refresh(cmd))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid refresh token");
    }

    @Test
    @DisplayName(" should throw when audience invalid")
    void testShouldThrowWhenAudienceInvalid() {
        RefreshCommand cmd = new RefreshCommand(REFRESH_TOKEN);

        JwtClaimsDTO badClaims = new JwtClaimsDTO(
                USERNAME, REFRESH_JTI, List.of("wrong_audience"),
                now.getEpochSecond(), now.getEpochSecond(), now.plusSeconds(3600).getEpochSecond(),
                List.of(), List.of());

        when(tokenProvider.validateAndGetClaims(REFRESH_TOKEN)).thenReturn(Optional.of(badClaims));
        when(props.refreshAudience()).thenReturn("refresh_audience");

        assertThatThrownBy(() -> refreshService.refresh(cmd))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid refresh token audience");
    }

    @Test
    @DisplayName(" should throw when refresh token not exists in store")
    void testShouldThrowWhenTokenNotExists() {
        RefreshCommand cmd = new RefreshCommand(REFRESH_TOKEN);

        JwtClaimsDTO claims = new JwtClaimsDTO(
                USERNAME, REFRESH_JTI, List.of("refresh_audience"),
                now.getEpochSecond(), now.getEpochSecond(), now.plusSeconds(3600).getEpochSecond(),
                List.of(), List.of());

        when(tokenProvider.validateAndGetClaims(REFRESH_TOKEN)).thenReturn(Optional.of(claims));
        when(refreshTokenStore.exists(REFRESH_JTI)).thenReturn(false);
        when(props.refreshAudience()).thenReturn("refresh_audience");

        assertThatThrownBy(() -> refreshService.refresh(cmd))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Refresh token not found (revoked or expired)");
    }

    @Test
    @DisplayName(" should throw when refresh token already revoked")
    void testShouldThrowWhenTokenRevoked() {
        RefreshCommand cmd = new RefreshCommand(REFRESH_TOKEN);

        JwtClaimsDTO claims = new JwtClaimsDTO(
                USERNAME, REFRESH_JTI, List.of("refresh_audience"),
                now.getEpochSecond(), now.getEpochSecond(), now.plusSeconds(3600).getEpochSecond(),
                List.of(), List.of());

        when(tokenProvider.validateAndGetClaims(REFRESH_TOKEN)).thenReturn(Optional.of(claims));
        when(refreshTokenStore.exists(REFRESH_JTI)).thenReturn(true);
        when(blacklist.isRevoked(REFRESH_JTI)).thenReturn(true);
        when(props.refreshAudience()).thenReturn("refresh_audience");

        assertThatThrownBy(() -> refreshService.refresh(cmd))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Refresh token revoked or re-used");
    }
}
