package com.lanny.spring_security_template.application.auth.service;

import java.util.UUID;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.command.RegisterCommand;
import com.lanny.spring_security_template.application.auth.port.in.AuthUseCase;
import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;
import com.lanny.spring_security_template.application.auth.query.MeQuery;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.result.MeResult;
import com.lanny.spring_security_template.domain.event.SecurityEvent;
import com.lanny.spring_security_template.domain.exception.UserLockedException;
import com.lanny.spring_security_template.domain.time.ClockProvider;

/**
 * <h1>AuthUseCaseLoggingDecorator</h1>
 *
 * <p>
 * Enterprise-grade decorator that enriches the {@link AuthUseCase} with:
 * </p>
 *
 * <ul>
 * <li><b>Structured security logging</b> (OWASP ASVS 2.10 compliance)</li>
 * <li><b>MDC trace correlation</b> for distributed observability</li>
 * <li><b>Unified security audit events</b> published via
 * {@link AuditEventPublisher}</li>
 * <li><b>Error-aware log severity</b> (INFO / WARN / ERROR based on event
 * type)</li>
 * </ul>
 *
 * <p>
 * This decorator contains <b>all cross-cutting concerns</b> related to
 * authentication observability.
 * The underlying {@link AuthUseCaseImpl} remains a pure business component:
 * no logging, no auditing, no framework imports, no MDC.
 * </p>
 *
 * <hr>
 *
 * <h2>🌐 Architecture Role</h2>
 *
 * <pre>
 *               +---------------------------+
 *               |      AuthUseCaseImpl      |
 *               | (pure logic, no logs)     |
 *               +-------------+-------------+
 *                             ^
 *                             | Decorator
 * +--------------------------------------------------------------+
 * |            AuthUseCaseLoggingDecorator                       |
 * | - Logs all auth events                                       |
 * | - Injects MDC (traceId, username, operation)                 |
 * | - Publishes audit events (Login, Refresh, Password, etc.)    |
 * | - Handles structured error logging                           |
 * +--------------------------------------------------------------+
 * </pre>
 *
 * <hr>
 *
 * <h2>🔐 OWASP ASVS Security Compliance</h2>
 *
 * <ul>
 * <li><b>ASVS 2.10</b>: Authentication events must be logged</li>
 * <li><b>ASVS 2.10.2</b>: Logs must include correlation identifiers</li>
 * <li><b>ASVS 2.10.4</b>: Log failed authentication attempts</li>
 * <li><b>ASVS 2.9</b>: Token issuance and refresh operations must be
 * auditable</li>
 * </ul>
 *
 * <hr>
 *
 * <h2>🧵 MDC Strategy</h2>
 *
 * <p>
 * Each public method (login, refresh, me, etc.) wraps the operation inside an
 * MDC block that:
 * </p>
 *
 * <ol>
 * <li>Generates a <b>traceId</b></li>
 * <li>Adds contextual information (username or operation)</li>
 * <li>Clears MDC after execution (even on exceptions)</li>
 * </ol>
 *
 * <p>
 * This prevents MDC leakage between threads in servlet engines or reactor
 * pools.
 * </p>
 *
 * <hr>
 *
 * <h2>🚫 Not Responsible For</h2>
 *
 * <ul>
 * <li>Credential validation</li>
 * <li>Token creation or rotation</li>
 * <li>User persistence</li>
 * <li>Business rules</li>
 * <li>Transactions</li>
 * </ul>
 *
 * <hr>
 *
 * <h2>💡 When to Extend This Decorator</h2>
 *
 * <ul>
 * <li>Integrating with SIEM (Elastic, Splunk, Datadog)</li>
 * <li>Capturing IP, device fingerprint, or geolocation</li>
 * <li>Propagating correlation IDs from API Gateway</li>
 * </ul>
 *
 */
public class AuthUseCaseLoggingDecorator implements AuthUseCase {

        private static final Logger log = LoggerFactory.getLogger(AuthUseCaseLoggingDecorator.class);

        private final AuthUseCase target;
        private final AuditEventPublisher audit;
        private final ClockProvider clock;

        public AuthUseCaseLoggingDecorator(
                        AuthUseCase target,
                        AuditEventPublisher audit,
                        ClockProvider clock) {
                this.target = target;
                this.audit = audit;
                this.clock = clock;
        }

        /*
         * ============================================================
         * MDC HELPER
         * ============================================================
         */
        private <T> T withMdc(String key, String value, Supplier<T> action) {
                String traceId = UUID.randomUUID().toString();
                MDC.put("traceId", traceId);
                MDC.put(key, value);

                try {
                        return action.get();
                } finally {
                        MDC.remove("traceId");
                        MDC.remove(key);
                }
        }

        /*
         * ============================================================
         * LOGIN
         * ============================================================
         */
        @Override
        public JwtResult login(LoginCommand cmd) {
                return withMdc("username", cmd.username(), () -> {

                        log.info("[AUTH_LOGIN_REQUEST] user={} trace={}", cmd.username(), MDC.get("traceId"));

                        audit.publishAuthEvent(
                                        SecurityEvent.LOGIN_ATTEMPT.name(),
                                        cmd.username(),
                                        clock.now(),
                                        "Login attempt");

                        log.debug("[AUTH_VALIDATION] user={} trace={}", cmd.username(), MDC.get("traceId"));

                        try {
                                JwtResult result = target.login(cmd);

                                log.info("[AUTH_VALIDATION_OK] user={} trace={}", cmd.username(), MDC.get("traceId"));
                                audit.publishAuthEvent(
                                                SecurityEvent.LOGIN_SUCCESS.name(),
                                                cmd.username(),
                                                clock.now(),
                                                "Login successful");

                                log.info("[AUTH_LOGIN_SUCCESS] user={} trace={}", cmd.username(), MDC.get("traceId"));
                                return result;

                        } catch (UserLockedException ex) {

                                log.warn("[AUTH_LOCKED] user={} trace={} reason=user_locked",
                                                cmd.username(), MDC.get("traceId"));

                                audit.publishAuthEvent(
                                                SecurityEvent.USER_LOCKED.name(),
                                                cmd.username(),
                                                clock.now(),
                                                "User attempted login while locked");

                                throw ex;

                        } catch (RuntimeException ex) {

                                log.error("[AUTH_LOGIN_FAILURE] user={} trace={} reason={}",
                                                cmd.username(), MDC.get("traceId"), ex.getMessage());

                                audit.publishAuthEvent(
                                                SecurityEvent.LOGIN_FAILURE.name(),
                                                cmd.username(),
                                                clock.now(),
                                                ex.getMessage());

                                throw ex;
                        }
                });
        }

        /*
         * ============================================================
         * REFRESH
         * ============================================================
         */
        @Override
        public JwtResult refresh(RefreshCommand cmd) {
                return withMdc("operation", "refresh", () -> {

                        log.info("[AUTH_REFRESH_REQUEST] trace={}", MDC.get("traceId"));

                        audit.publishAuthEvent(
                                        SecurityEvent.TOKEN_REFRESH_ATTEMPT.name(),
                                        "unknown",
                                        clock.now(),
                                        "Refresh attempt");

                        try {
                                JwtResult result = target.refresh(cmd);

                                log.info("[AUTH_REFRESH_SUCCESS] trace={}", MDC.get("traceId"));

                                audit.publishAuthEvent(
                                                SecurityEvent.TOKEN_REFRESH.name(),
                                                "unknown",
                                                clock.now(),
                                                "Token refreshed successfully");

                                return result;

                        } catch (RuntimeException ex) {

                                log.error("[AUTH_REFRESH_TOKEN_INVALID] trace={} reason={}",
                                                MDC.get("traceId"), ex.getMessage());

                                audit.publishAuthEvent(
                                                SecurityEvent.TOKEN_REFRESH_FAILED.name(),
                                                "unknown",
                                                clock.now(),
                                                ex.getMessage());

                                log.error("[AUTH_REFRESH_FAILURE] trace={} reason={}",
                                                MDC.get("traceId"), ex.getMessage());

                                throw ex;
                        }
                });
        }

        /*
         * ============================================================
         * ME (PROFILE)
         * ============================================================
         */
        @Override
        public MeResult me(MeQuery query) {
                return withMdc("username", query.username(), () -> {
                        log.debug("[AUTH_ME_REQUEST] user={} trace={}", query.username(), MDC.get("traceId"));
                        return target.me(query);
                });
        }

        /*
         * ============================================================
         * REGISTER DEV USER
         * ============================================================
         */
        @Override
        public void registerDev(RegisterCommand cmd) {
                withMdc("username", cmd.username(), () -> {

                        log.info("[DEV_REGISTER_REQUEST] user={} trace={}", cmd.username(), MDC.get("traceId"));

                        try {
                                target.registerDev(cmd);

                                audit.publishAuthEvent(
                                                SecurityEvent.USER_REGISTERED.name(),
                                                cmd.username(),
                                                clock.now(),
                                                "Developer seed user registered successfully");

                                log.info("[DEV_REGISTER_SUCCESS] user={} trace={}", cmd.username(), MDC.get("traceId"));
                                return null;

                        } catch (RuntimeException ex) {
                                log.error("[DEV_REGISTER_FAILURE] user={} trace={} reason={}",
                                                cmd.username(), MDC.get("traceId"), ex.getMessage());
                                throw ex;
                        }
                });
        }

        /*
         * ============================================================
         * CHANGE PASSWORD
         * ============================================================
         */
        @Override
        public void changePassword(String username, String oldPassword, String newPassword) {
                withMdc("username", username, () -> {

                        log.info("[AUTH_CHANGE_PASSWORD_REQUEST] user={} trace={}", username, MDC.get("traceId"));

                        audit.publishAuthEvent(
                                        SecurityEvent.PASSWORD_CHANGE_ATTEMPT.name(),
                                        username,
                                        clock.now(),
                                        "Password change attempt");

                        try {
                                target.changePassword(username, oldPassword, newPassword);

                                audit.publishAuthEvent(
                                                SecurityEvent.PASSWORD_CHANGED.name(),
                                                username,
                                                clock.now(),
                                                "Password changed successfully");

                                log.info("[AUTH_CHANGE_PASSWORD_SUCCESS] user={} trace={}", username,
                                                MDC.get("traceId"));
                                return null;

                        } catch (RuntimeException ex) {

                                log.error("[AUTH_CHANGE_PASSWORD_FAILURE] user={} trace={} reason={}",
                                                username, MDC.get("traceId"), ex.getMessage());

                                audit.publishAuthEvent(
                                                SecurityEvent.PASSWORD_CHANGE_FAILED.name(),
                                                username,
                                                clock.now(),
                                                ex.getMessage());

                                throw ex;
                        }
                });
        }
}
