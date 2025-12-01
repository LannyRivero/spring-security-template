package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.lanny.spring_security_template.application.auth.service.*;
import com.lanny.spring_security_template.application.auth.policy.*;
import com.lanny.spring_security_template.application.auth.port.out.*;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.domain.time.ClockProvider;

@Configuration
public class AuthApplicationConfig {

    /*
     * ============================================================
     * CORE VALIDATORS & METRICS
     * ============================================================
     */
    @Bean
    public AuthenticationValidator authenticationValidator(
            UserAccountGateway userAccountGateway,
            PasswordHasher passwordHasher) {
        return new AuthenticationValidator(userAccountGateway, passwordHasher);
    }

    @Bean
    public LoginMetricsRecorder loginMetricsRecorder(AuthMetricsService metricsService) {
        return new LoginMetricsRecorder(metricsService);
    }

    /*
     * ============================================================
     * TOKEN ISSUANCE
     * ============================================================
     */
    @Bean
    public TokenIssuer tokenIssuer(
            TokenProvider tokenProvider,
            ClockProvider clockProvider,
            TokenPolicyProperties tokenPolicy) {
        return new TokenIssuer(tokenProvider, clockProvider, tokenPolicy);
    }

    /*
     * ============================================================
     * SESSION MANAGEMENT
     * ============================================================
     */
    @Bean
    public SessionManager sessionManager(
            SessionRegistryGateway sessionRegistry,
            TokenBlacklistGateway blacklist,
            SessionPolicy policy,
            RefreshTokenStore refreshTokenStore) {
        return new SessionManager(sessionRegistry, blacklist, policy, refreshTokenStore);
    }

    @Bean
    public TokenSessionCreator tokenSessionCreator(
            RoleProvider roleProvider,
            ScopePolicy scopePolicy,
            TokenIssuer issuer,
            SessionManager sessionManager,
            RefreshTokenStore store) {
        return new TokenSessionCreator(roleProvider, scopePolicy, issuer, sessionManager, store);
    }

    /*
     * ============================================================
     * LOGIN SERVICE
     * ============================================================
     */
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

    /*
     * ============================================================
     * REFRESH TOKEN SERVICES
     * ============================================================
     */
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

    /*
     * ============================================================
     * ME SERVICE
     * ============================================================
     */
    @Bean
    public MeService meService(
            UserAccountGateway userAccountGateway,
            RoleProvider roleProvider,
            ScopePolicy scopePolicy) {
        return new MeService(userAccountGateway, roleProvider, scopePolicy);
    }

    /*
     * ============================================================
     * CHANGE PASSWORD SERVICE
     * ============================================================
     */
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

    /*
     * ============================================================
     * DEV REGISTER SERVICE
     * ============================================================
     */
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
