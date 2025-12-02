package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.lanny.spring_security_template.application.auth.policy.LoginAttemptPolicy;
import com.lanny.spring_security_template.application.auth.policy.PasswordPolicy;
import com.lanny.spring_security_template.application.auth.policy.RefreshTokenPolicy;
import com.lanny.spring_security_template.application.auth.policy.RotationPolicy;
import com.lanny.spring_security_template.application.auth.policy.SessionPolicy;
import com.lanny.spring_security_template.application.auth.policy.TokenPolicyProperties;
import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;
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

/**
 * =====================================================================
 * AuthApplicationConfig
 * =====================================================================
 *
 * Central configuration class wiring all **Application Layer services**
 * for the authentication subsystem.
 *
 * <p>
 * This class is the composition root for:
 * </p>
 * <ul>
 * <li>Login and Authentication validation</li>
 * <li>Token issuance and session lifecycle</li>
 * <li>Refresh-token rotation and validation</li>
 * <li>Me-profile lookup</li>
 * <li>Password change flow</li>
 * <li>Developer registration (dev-only)</li>
 * </ul>
 *
 * <h2>Architectural Role</h2>
 * <p>
 * This configuration belongs strictly to the <b>Infrastructure Layer</b>,
 * acting as the assembler for Application Layer services using:
 * <i>ports, policies, gateways, and domain services</i>.
 * </p>
 *
 * <h2>Security Compliance</h2>
 * <ul>
 * <li>OWASP ASVS 2.1 – Centralized authentication mechanisms</li>
 * <li>OWASP ASVS 2.8 – Token lifecycle and secure session management</li>
 * <li>Clean Architecture – No framework leakage into the Application Layer</li>
 * </ul>
 *
 * <h2>Notes</h2>
 * <ul>
 * <li>All dependencies are injected via ports & policies.</li>
 * <li>No infrastructure logic is allowed inside services created here.</li>
 * <li>This class must remain free of business logic.</li>
 * </ul>
 */
@Configuration
public class AuthApplicationConfig {

    // ============================================================
    // CORE VALIDATORS & METRICS
    // ============================================================

    /** Validator used during user authentication. */
    @Bean
    public AuthenticationValidator authenticationValidator(
            UserAccountGateway userAccountGateway,
            PasswordHasher passwordHasher) {
        return new AuthenticationValidator(userAccountGateway, passwordHasher);
    }

    /** Recorder for login-related metrics (success/failure). */
    @Bean
    public LoginMetricsRecorder loginMetricsRecorder(AuthMetricsService metricsService) {
        return new LoginMetricsRecorder(metricsService);
    }

    // ============================================================
    // TOKEN ISSUANCE
    // ============================================================

    /** Issues access and refresh tokens according to token policies. */
    @Bean
    public TokenIssuer tokenIssuer(
            TokenProvider tokenProvider,
            ClockProvider clockProvider,
            TokenPolicyProperties tokenPolicy) {
        return new TokenIssuer(tokenProvider, clockProvider, tokenPolicy);
    }

    // ============================================================
    // SESSION MANAGEMENT
    // ============================================================

    /** Tracks active sessions, handles blacklist + refresh token store. */
    @Bean
    public SessionManager sessionManager(
            SessionRegistryGateway sessionRegistry,
            TokenBlacklistGateway blacklist,
            SessionPolicy policy,
            RefreshTokenStore refreshTokenStore) {
        return new SessionManager(sessionRegistry, blacklist, policy, refreshTokenStore);
    }

    /** Creates token sessions after login or registration. */
    @Bean
    public TokenSessionCreator tokenSessionCreator(
            RoleProvider roleProvider,
            ScopePolicy scopePolicy,
            TokenIssuer issuer,
            SessionManager sessionManager,
            RefreshTokenStore store) {
        return new TokenSessionCreator(roleProvider, scopePolicy, issuer, sessionManager, store);
    }

    // ============================================================
    // LOGIN SERVICE
    // ============================================================

    /** Main login flow orchestrator. */
    @Bean
    public LoginService loginService(
            AuthenticationValidator validator,
            TokenSessionCreator tokenSessionCreator,
            LoginMetricsRecorder loginMetricsRecorder,
            LoginAttemptPolicy loginAttemptPolicy) {
        return new LoginService(
                validator,
                tokenSessionCreator,
                loginMetricsRecorder,
                loginAttemptPolicy);
    }

    // ============================================================
    // REFRESH TOKEN SERVICES
    // ============================================================

    @Bean
    public RefreshTokenValidator refreshTokenValidator(
            RefreshTokenStore store,
            TokenBlacklistGateway blacklist,
            RefreshTokenPolicy policy) {
        return new RefreshTokenValidator(store, blacklist, policy);
    }

    @Bean
    public TokenRotationHandler tokenRotationHandler(
            RoleProvider roleProvider,
            ScopePolicy scopePolicy,
            TokenIssuer tokenIssuer,
            RefreshTokenStore store,
            SessionRegistryGateway registry,
            TokenBlacklistGateway blacklist,
            RotationPolicy rotationPolicy) {
        return new TokenRotationHandler(
                roleProvider,
                scopePolicy,
                tokenIssuer,
                store,
                registry,
                blacklist,
                rotationPolicy);
    }

    @Bean
    public TokenRefreshResultFactory tokenRefreshResultFactory(
            RoleProvider roleProvider,
            ScopePolicy scopePolicy,
            TokenProvider tokenProvider,
            ClockProvider clockProvider,
            TokenPolicyProperties tokenPolicy) {
        return new TokenRefreshResultFactory(
                roleProvider,
                scopePolicy,
                tokenProvider,
                clockProvider,
                tokenPolicy);
    }

    @Bean
    public RefreshService refreshService(
            TokenProvider tokenProvider,
            RefreshTokenValidator validator,
            TokenRotationHandler rotationHandler,
            TokenRefreshResultFactory resultFactory) {

        return new RefreshService(tokenProvider, validator, rotationHandler, resultFactory);
    }

    // ============================================================
    // ME SERVICE
    // ============================================================

    @Bean
    public MeService meService(
            UserAccountGateway userAccountGateway,
            RoleProvider roleProvider,
            ScopePolicy scopePolicy) {
        return new MeService(userAccountGateway, roleProvider, scopePolicy);
    }

    // ============================================================
    // CHANGE PASSWORD SERVICE
    // ============================================================

    @Bean
    public ChangePasswordService changePasswordService(
            UserAccountGateway userGateway,
            RefreshTokenStore refreshStore,
            PasswordHasher passwordHasher,
            PasswordPolicy passwordPolicy) {
        return new ChangePasswordService(
                userGateway,
                refreshStore,
                passwordHasher,
                passwordPolicy);
    }

    // ============================================================
    // DEV REGISTER SERVICE
    // ============================================================

    @Bean
    public DevRegisterService devRegisterService(
            UserAccountGateway gateway,
            PasswordHasher passwordHasher,
            PasswordPolicy passwordPolicy,
            AuthMetricsService metrics) {
        return new DevRegisterService(
                gateway,
                passwordHasher,
                metrics,
                passwordPolicy);
    }
}
