package com.lanny.spring_security_template.application.auth.service;

import java.time.Instant;

import org.slf4j.MDC;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.lanny.spring_security_template.application.auth.policy.PasswordPolicy;
import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;
import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.event.SecurityEvent;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.domain.time.ClockProvider;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Handles secure password change for authenticated users.
 *
 * <p>
 * Implements password policy enforcement and ensures all sessions
 * are invalidated after a successful change, per OWASP ASVS 2.7.2.
 * </p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ChangePasswordService {

    private final UserAccountGateway userAccountGateway;
    private final RefreshTokenStore refreshTokenStore;
    private final PasswordHasher passwordHasher;
    private final PasswordPolicy passwordPolicy;
    private final AuthMetricsService metrics;
    private final ClockProvider clockProvider;
    private final AuditEventPublisher auditEventPublisher;

    @Transactional
    public void changePassword(String username, String currentPassword, String newPassword) {
        String traceId = MDC.get("traceId");
        Instant now = clockProvider.now();

        if (username == null || username.isBlank() || newPassword == null || newPassword.isBlank()) {
            throw new IllegalArgumentException("Username and passwords must not be blank");
        }

        log.info("[EVENT=PASSWORD_CHANGE_REQUEST] user={} trace={} ts={}", username, traceId, now);

        try {
            // 1️ Retrieve user (generic error → prevent user enumeration)
            User user = userAccountGateway.findByUsernameOrEmail(username)
                    .orElseThrow(() -> new InvalidCredentialsException("Invalid current password"));

            // 2️ Verify current password
            if (!passwordHasher.matches(currentPassword, user.passwordHash().value())) {
                metrics.recordLoginFailure();
                auditEventPublisher.publishAuthEvent(
                        SecurityEvent.PASSWORD_CHANGE_FAILED.name(),
                        username,
                        now,
                        "Incorrect current password");
                log.warn("[EVENT=PASSWORD_CHANGE_FAIL] user={} trace={} reason=invalid_password ts={}", username,
                        traceId, now);
                throw new InvalidCredentialsException("Invalid current password");
            }

            // 3️ Validate new password policy
            passwordPolicy.validate(newPassword);

            // 4️ Hash new password and update
            PasswordHash newHash = PasswordHash.of(passwordHasher.hash(newPassword));
            User updatedUser = user.withChangedPassword(newHash);
            userAccountGateway.update(updatedUser);

            // 5️Invalidate all sessions
            refreshTokenStore.deleteAllForUser(username);
            metrics.recordSessionRevoked();
            metrics.recordPasswordChange();

            // 6️ Publish audit and structured log
            auditEventPublisher.publishAuthEvent(
                    SecurityEvent.PASSWORD_CHANGED.name(),
                    username,
                    now,
                    "Password changed successfully; all sessions invalidated");
            log.info("[EVENT=PASSWORD_CHANGE_SUCCESS] user={} trace={} ts={}", username, traceId, now);
        } finally {
            MDC.clear();
        }
    }
}
