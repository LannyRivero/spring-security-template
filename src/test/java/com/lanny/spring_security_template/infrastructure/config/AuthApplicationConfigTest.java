package com.lanny.spring_security_template.infrastructure.config;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import com.lanny.spring_security_template.application.auth.policy.LoginAttemptPolicy;
import com.lanny.spring_security_template.application.auth.policy.PasswordPolicy;
import com.lanny.spring_security_template.application.auth.policy.RefreshTokenPolicy;
import com.lanny.spring_security_template.application.auth.policy.RotationPolicy;
import com.lanny.spring_security_template.application.auth.policy.SessionPolicy;
import com.lanny.spring_security_template.application.auth.policy.TokenPolicyProperties;
import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenConsumptionPort;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.application.auth.port.out.SessionRegistryGateway;
import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.application.auth.service.AuthenticationValidator;
import com.lanny.spring_security_template.application.auth.service.ChangePasswordService;
import com.lanny.spring_security_template.application.auth.service.DevRegisterService;
import com.lanny.spring_security_template.application.auth.service.LoginMetricsRecorder;
import com.lanny.spring_security_template.application.auth.service.LoginService;
import com.lanny.spring_security_template.application.auth.service.MeService;
import com.lanny.spring_security_template.application.auth.service.RefreshService;
import com.lanny.spring_security_template.application.auth.service.RefreshTokenValidator;
import com.lanny.spring_security_template.application.auth.service.SessionManager;
import com.lanny.spring_security_template.application.auth.service.TokenIssuer;
import com.lanny.spring_security_template.application.auth.service.TokenRefreshResultFactory;
import com.lanny.spring_security_template.application.auth.service.TokenRotationHandler;
import com.lanny.spring_security_template.application.auth.service.TokenSessionCreator;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.domain.time.ClockProvider;

class AuthApplicationConfigTest {

        private AuthApplicationConfig config;

        // Mocks for all dependencies required by the config methods
        @Mock
        private UserAccountGateway userGateway;
        @Mock
        private PasswordHasher passwordHasher;
        @Mock
        private AuthMetricsService metricsService;
        @Mock
        private TokenProvider tokenProvider;
        @Mock
        private ClockProvider clockProvider;
        @Mock
        private TokenPolicyProperties tokenPolicy;
        @Mock
        private SessionRegistryGateway sessionRegistry;
        @Mock
        private TokenBlacklistGateway blacklist;
        @Mock
        private SessionPolicy sessionPolicy;
        @Mock
        private RefreshTokenStore refreshTokenStore;
        @Mock
        private RoleProvider roleProvider;
        @Mock
        private ScopePolicy scopePolicy;
        @Mock
        private LoginAttemptPolicy loginAttemptPolicy;
        @Mock
        private RefreshTokenPolicy refreshTokenPolicy;
        @Mock
        private RotationPolicy rotationPolicy;

        @BeforeEach
        void setUp() {
                MockitoAnnotations.openMocks(this);
                config = new AuthApplicationConfig();
        }

        // --------------------------------------------------------------
        // VALIDATORS & METRICS
        // --------------------------------------------------------------
        @Test
        @DisplayName("testShouldCreateAuthenticationValidatorBean")
        void testShouldCreateAuthenticationValidatorBean() {
                var bean = config.authenticationValidator(userGateway, passwordHasher);

                assertThat(bean)
                                .isNotNull()
                                .isInstanceOf(AuthenticationValidator.class);
        }

        @Test
        @DisplayName("testShouldCreateLoginMetricsRecorderBean")
        void testShouldCreateLoginMetricsRecorderBean() {
                var bean = config.loginMetricsRecorder(metricsService);

                assertThat(bean)
                                .isNotNull()
                                .isInstanceOf(LoginMetricsRecorder.class);
        }

        // --------------------------------------------------------------
        // TOKEN ISSUER
        // --------------------------------------------------------------
        @Test
        @DisplayName("testShouldCreateTokenIssuerBean")
        void testShouldCreateTokenIssuerBean() {
                var bean = config.tokenIssuer(tokenProvider, clockProvider, tokenPolicy);

                assertThat(bean)
                                .isNotNull()
                                .isInstanceOf(TokenIssuer.class);
        }

        // --------------------------------------------------------------
        // SESSION MANAGEMENT
        // --------------------------------------------------------------
        @Test
        @DisplayName("testShouldCreateSessionManagerBean")
        void testShouldCreateSessionManagerBean() {
                var bean = config.sessionManager(sessionRegistry, blacklist, sessionPolicy, refreshTokenStore);

                assertThat(bean)
                                .isNotNull()
                                .isInstanceOf(SessionManager.class);
        }

        @Test
        @DisplayName("testShouldCreateTokenSessionCreatorBean")
        void testShouldCreateTokenSessionCreatorBean() {
                var bean = config.tokenSessionCreator(
                                roleProvider,
                                scopePolicy,
                                tokenIssuer(),
                                sessionManager(),
                                refreshTokenStore);

                assertThat(bean)
                                .isNotNull()
                                .isInstanceOf(TokenSessionCreator.class);
        }

        private SessionManager sessionManager() {
                return new SessionManager(sessionRegistry, blacklist, sessionPolicy, refreshTokenStore);
        }

        // --------------------------------------------------------------
        // LOGIN SERVICE
        // --------------------------------------------------------------
        @Test
        @DisplayName("testShouldCreateLoginServiceBean")
        void testShouldCreateLoginServiceBean() {
                var validator = config.authenticationValidator(userGateway, passwordHasher);
                var recorder = config.loginMetricsRecorder(metricsService);
                var sessionCreator = new TokenSessionCreator(roleProvider, scopePolicy, tokenIssuer(), sessionManager(),
                                refreshTokenStore);

                var bean = config.loginService(validator, sessionCreator, recorder, loginAttemptPolicy);

                assertThat(bean)
                                .isNotNull()
                                .isInstanceOf(LoginService.class);
        }

        // --------------------------------------------------------------
        // REFRESH TOKEN SERVICES
        // --------------------------------------------------------------
        @Test
        @DisplayName("testShouldCreateRefreshTokenValidatorBean")
        void testShouldCreateRefreshTokenValidatorBean() {
                var bean = config.refreshTokenValidator(refreshTokenPolicy);

                assertThat(bean)
                                .isNotNull()
                                .isInstanceOf(RefreshTokenValidator.class);
        }

        @Test
        @DisplayName("testShouldCreateTokenRotationHandlerBean")
        void testShouldCreateTokenRotationHandlerBean() {
                var bean = config.tokenRotationHandler(
                                roleProvider,
                                scopePolicy,
                                new TokenIssuer(tokenProvider, clockProvider, tokenPolicy),
                                refreshTokenStore,
                                sessionRegistry,
                                blacklist,
                                rotationPolicy);

                assertThat(bean)
                                .isNotNull()
                                .isInstanceOf(TokenRotationHandler.class);
        }

        @Test
        @DisplayName("testShouldCreateTokenRefreshResultFactoryBean")
        void testShouldCreateTokenRefreshResultFactoryBean() {
                var bean = config.tokenRefreshResultFactory(
                                roleProvider,
                                scopePolicy,
                                tokenProvider,
                                clockProvider,
                                tokenPolicy);

                assertThat(bean)
                                .isNotNull()
                                .isInstanceOf(TokenRefreshResultFactory.class);
        }

        @Test
        @DisplayName("testShouldCreateRefreshServiceBean")
        void testShouldCreateRefreshServiceBean() {
                var bean = config.refreshService(
                                tokenProvider,
                                new RefreshTokenValidator(refreshTokenPolicy),
                                refreshTokenStore,
                                new TokenRotationHandler(roleProvider, scopePolicy, tokenIssuer(), refreshTokenStore,
                                                sessionRegistry,
                                                blacklist, rotationPolicy),
                                new TokenRefreshResultFactory(roleProvider, scopePolicy, tokenProvider, clockProvider,
                                                tokenPolicy),
                                mock(RefreshTokenConsumptionPort.class));

                assertThat(bean)
                                .isNotNull()
                                .isInstanceOf(RefreshService.class);
        }

        private TokenIssuer tokenIssuer() {
                return new TokenIssuer(tokenProvider, clockProvider, tokenPolicy);
        }

        // --------------------------------------------------------------
        // ME SERVICE
        // --------------------------------------------------------------
        @Test
        @DisplayName("testShouldCreateMeServiceBean")
        void testShouldCreateMeServiceBean() {
                var bean = config.meService(userGateway, roleProvider, scopePolicy);

                assertThat(bean)
                                .isNotNull()
                                .isInstanceOf(MeService.class);
        }

        // --------------------------------------------------------------
        // CHANGE PASSWORD SERVICE
        // --------------------------------------------------------------
        @Test
        @DisplayName("testShouldCreateChangePasswordServiceBean")
        void testShouldCreateChangePasswordServiceBean() {
                var bean = config.changePasswordService(userGateway, refreshTokenStore, passwordHasher,
                                passwordPolicy());

                assertThat(bean)
                                .isNotNull()
                                .isInstanceOf(ChangePasswordService.class);
        }

        private PasswordPolicy passwordPolicy() {
                return raw -> {
                };
        }

        // --------------------------------------------------------------
        // DEV REGISTER SERVICE
        // --------------------------------------------------------------
        @Test
        @DisplayName("testShouldCreateDevRegisterServiceBean")
        void testShouldCreateDevRegisterServiceBean() {
                var bean = config.devRegisterService(userGateway, passwordHasher, passwordPolicy(), metricsService);

                assertThat(bean)
                                .isNotNull()
                                .isInstanceOf(DevRegisterService.class);
        }
}
