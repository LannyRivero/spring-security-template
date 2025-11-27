package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.policy.PasswordPolicy;
import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;
import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;
import com.lanny.spring_security_template.domain.time.ClockProvider;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Handles secure password change for authenticated users.
 *
 * <p>
 * This service validates the current password, applies the configured
 * {@link PasswordPolicy}, hashes the new password, updates the user record,
 * and invalidates all existing refresh tokens to ensure session rotation.
 * </p>
 *
 * <p>
 * Fully compliant with:
 * <ul>
 *   <li>OWASP ASVS 2.7.2 — "Invalidate active sessions after password change"</li>
 *   <li>OWASP ASVS 2.8.3 — "Enforce strong password policy"</li>
 * </ul>
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

    /**
     * Changes the password for a given authenticated user.
     *
     * @param username        username of the authenticated user
     * @param currentPassword current raw password provided by the user
     * @param newPassword     desired new password (raw)
     * @throws InvalidCredentialsException if current password does not match
     * @throws IllegalArgumentException    if new password violates {@link PasswordPolicy}
     */
    @Transactional
    public void changePassword(String username, String currentPassword, String newPassword) {
        String traceId = MDC.get("traceId");
        Instant now = clockProvider.now();

        log.info("[PASSWORD_CHANGE_REQUEST] user={} trace={}", username, traceId);

        // 1️⃣ Retrieve user
        User user = userAccountGateway.findByUsernameOrEmail(username)
                .orElseThrow(() -> new InvalidCredentialsException("User not found: " + username));

        // 2️⃣ Verify current password
        if (!passwordHasher.matches(currentPassword, user.passwordHash().value())) {
            metrics.recordLoginFailure();
            auditEventPublisher.publishAuthEvent(
                    "PASSWORD_CHANGE_FAILED",
                    username,
                    now,
                    "Incorrect current password");
            log.warn("[PASSWORD_CHANGE_FAIL] user={} reason=invalid_current_password trace={}", username, traceId);
            throw new InvalidCredentialsException("Invalid current password");
        }

        // 3️⃣ Validate new password strength
        passwordPolicy.validate(newPassword);

        // 4️⃣ Hash and update password
        PasswordHash newHash = PasswordHash.of(passwordHasher.hash(newPassword));
        User updatedUser = user.withChangedPassword(newHash);
        userAccountGateway.update(updatedUser);

        // 5️⃣ Invalidate all active refresh tokens / sessions
        refreshTokenStore.deleteAllForUser(username);
        metrics.recordSessionRevoked();

        // 6️⃣ Publish audit and log event
        auditEventPublisher.publishAuthEvent(
                "PASSWORD_CHANGED",
                username,
                now,
                "Password changed successfully; all sessions invalidated");

        log.info("[PASSWORD_CHANGE_SUCCESS] user={} trace={}", username, traceId);
    }
}

