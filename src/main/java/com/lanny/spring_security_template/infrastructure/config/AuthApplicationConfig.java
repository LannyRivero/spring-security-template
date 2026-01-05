package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Profile;

import com.lanny.spring_security_template.application.auth.policy.*;
import com.lanny.spring_security_template.application.auth.port.out.*;
import com.lanny.spring_security_template.application.auth.service.*;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.domain.time.ClockProvider;

/**
 * ============================================================
 * AUTHENTICATION & AUTHORIZATION — APPLICATION ASSEMBLY
 * ============================================================
 *
 * This class is the **composition root** of the Authentication module.
 * It wires all Application Services using:
 *
 * - Ports (in/out)
 * - Domain Services
 * - Security Policies
 *
 * No infrastructure-specific code is allowed here, keeping
 * Clean Architecture boundaries sharp and auditable.
 *
 * Suitable for:
 * - enterprise microservices
 * - multi-tenant setups
 * - high-security authentication systems
 *
 * Complies with:
 * - OWASP ASVS 2.x
 * - Clean Architecture
 * - DDD application layering
 */
@Configuration
public class AuthApplicationConfig {

    // ============================================================
    // VALIDATORS & METRICS
    // ============================================================

    /**
     * Validates user credentials during login.
     * No infrastructure leak.
     */
    @Bean
    public AuthenticationValidator authenticationValidator(
            UserAccountGateway userGateway,
            PasswordHasher passwordHasher) {

        return new AuthenticationValidator(userGateway, passwordHasher);
    }

    /**
     * Application-layer metrics recorder.
     * Decoupled from Micrometer via outbound port.
     */
    @Bean
    public LoginMetricsRecorder loginMetricsRecorder(AuthMetricsService metrics) {
        return new LoginMetricsRecorder(metrics);
    }

    // ============================================================
    // TOKEN ISSUANCE
    // ============================================================

    /**
     * Issues signed JWTs using a pure application-level contract.
     * TokenProvider (Nimbus, Jose4j, etc.) lives entirely in infra.
     *
     * Marked @Lazy to avoid future cyclic dependencies.
     */
    @Bean
    @Lazy
    public TokenIssuer tokenIssuer(
            TokenProvider tokenProvider,
            ClockProvider clockProvider,
            TokenPolicyProperties tokenPolicy) {

        return new TokenIssuer(tokenProvider, clockProvider, tokenPolicy);
    }

    // ============================================================
    // SESSION MANAGEMENT
    // ============================================================

    /**
     * Manages active sessions and token revocations.
     * High-level orchestration for refresh flow.
     */
    @Bean
    public SessionManager sessionManager(
            SessionRegistryGateway registry,
            TokenBlacklistGateway blacklist,
            SessionPolicy sessionPolicy,
            RefreshTokenStore refreshStore) {

        return new SessionManager(registry, blacklist, sessionPolicy, refreshStore);
    }

    /**
     * Creates token session (access + refresh) after login/registration.
     * Handles role + scope resolution.
     */
    @Bean
    public TokenSessionCreator tokenSessionCreator(
            RoleProvider roleProvider,
            ScopePolicy scopePolicy,
            TokenIssuer tokenIssuer,
            SessionManager sessionManager,
            RefreshTokenStore refreshStore) {

        return new TokenSessionCreator(roleProvider, scopePolicy, tokenIssuer, sessionManager, refreshStore);
    }

    // ============================================================
    // LOGIN USE CASE
    // ============================================================

    /**
     * The main login orchestration service.
     * Handles:
     * - credential validation
     * - metrics
     * - rate limiting policy
     */
    @Bean
    public LoginService loginService(
            AuthenticationValidator validator,
            TokenSessionCreator sessionCreator,
            LoginMetricsRecorder metricsRecorder,
            LoginAttemptPolicy loginAttemptPolicy) {

        return new LoginService(validator, sessionCreator, metricsRecorder, loginAttemptPolicy);
    }

    // ============================================================
    // REFRESH TOKEN FLOW
    // ============================================================

    @Bean
    public RefreshTokenValidator refreshTokenValidator(
            RefreshTokenPolicy policy) {

        return new RefreshTokenValidator(policy);
    }

    @Bean
    public TokenRotationHandler tokenRotationHandler(
            RoleProvider roleProvider,
            ScopePolicy scopePolicy,
            TokenIssuer issuer,
            RefreshTokenStore store,
            SessionRegistryGateway registry,
            TokenBlacklistGateway blacklist,
            RotationPolicy rotationPolicy) {

        return new TokenRotationHandler(roleProvider, scopePolicy, issuer, store, registry, blacklist, rotationPolicy);
    }

    @Bean
    public TokenRefreshResultFactory tokenRefreshResultFactory(
            RoleProvider roleProvider,
            ScopePolicy scopePolicy,
            TokenProvider tokenProvider,
            ClockProvider clockProvider,
            TokenPolicyProperties policy) {

        return new TokenRefreshResultFactory(roleProvider, scopePolicy, tokenProvider, clockProvider, policy);
    }

    @Bean
    public RefreshService refreshService(
            TokenProvider tokenProvider,
            RefreshTokenValidator validator,
            RefreshTokenStore refreshTokenStore,
            TokenRotationHandler rotationHandler,
            TokenRefreshResultFactory resultFactory,
            RefreshTokenConsumptionPort refreshTokenConsumption) {

        return new RefreshService(tokenProvider, validator, refreshTokenStore, rotationHandler, resultFactory, refreshTokenConsumption);
    }

    // ============================================================
    // ME PROFILE SERVICE
    // ============================================================

    @Bean
    public MeService meService(
            UserAccountGateway userGateway,
            RoleProvider roleProvider,
            ScopePolicy scopePolicy) {

        return new MeService(userGateway, roleProvider, scopePolicy);
    }

    // ============================================================
    // PASSWORD CHANGE SERVICE
    // ============================================================

    @Bean
    public ChangePasswordService changePasswordService(
            UserAccountGateway userGateway,
            RefreshTokenStore refreshStore,
            PasswordHasher hasher,
            PasswordPolicy passwordPolicy) {

        return new ChangePasswordService(userGateway, refreshStore, hasher, passwordPolicy);
    }

    // ============================================================
    // DEV-ONLY REGISTRATION (disabled in prod)
    // ============================================================

    @Bean
    @Profile({ "dev", "demo" })
    public DevRegisterService devRegisterService(
            UserAccountGateway gateway,
            PasswordHasher hasher,
            PasswordPolicy passwordPolicy,
            AuthMetricsService metrics) {

        return new DevRegisterService(gateway, hasher, metrics, passwordPolicy);
    }
}
