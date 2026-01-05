package com.lanny.spring_security_template.infrastructure.transactional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import com.lanny.spring_security_template.application.auth.port.out.ChangePasswordPort;
import com.lanny.spring_security_template.application.auth.service.ChangePasswordService;

import lombok.RequiredArgsConstructor;

/**
 * Infrastructure-level transactional adapter for ChangePasswordService.
 *
 * This adapter ensures:
 * - Explicitic transactional to prevent concurrent password changes
 * - Strong isolation to prevent concurrent password changes
 * -Atomic execution of password change + session/token invalidation
 * - Application layer remains framework-agnostic
 */
@Service
@RequiredArgsConstructor
public class ChangePasswordTransactionalAdapter implements ChangePasswordPort {

    private final ChangePasswordService delegate;

    /**
     * Changes a user's password inside a strong transactional boundary.
     * 
     * Banking rationale:
     * - Prevent concurrent password updates
     * -Avoid race conditions with refresh okens/active sessions
     * -Ensure atomicity (either everything commits or everything rolls back)
     *
     * @param username        target username
     * @param currentPassword current password (for verification)
     * @param newPassword     new password to set
     */
    @Transactional(isolation = Isolation.REPEATABLE_READ)
    public void changePassword(String username, String currentPassword, String newPassword) {
        delegate.changePassword(username, currentPassword, newPassword);
    }
}
