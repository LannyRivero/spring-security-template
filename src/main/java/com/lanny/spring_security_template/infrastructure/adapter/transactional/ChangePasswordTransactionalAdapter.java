package com.lanny.spring_security_template.infrastructure.adapter.transactional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import com.lanny.spring_security_template.application.auth.port.out.ChangePasswordPort;
import com.lanny.spring_security_template.application.auth.service.ChangePasswordService;

import lombok.RequiredArgsConstructor;

/**
 * Infrastructure-level transactional adapter for ChangePasswordService.
 *
 * <p>
 * This adapter ensures:
 * </p>
 * <ul>
 * <li>Explicit transactional boundary to prevent concurrent password
 * changes</li>
 * <li>Strong isolation to avoid race conditions</li>
 * <li>Atomic execution of password change and session/token invalidation</li>
 * <li>Application layer remains framework-agnostic</li>
 * </ul>
 */

@Service
@RequiredArgsConstructor
public class ChangePasswordTransactionalAdapter implements ChangePasswordPort {

    private final ChangePasswordService delegate;

    /**
     * Changes a user's password inside a strong transactional boundary.
     *
     * <p>
     * Security rationale:
     * </p>
     * <ul>
     * <li>Prevent concurrent password updates</li>
     * <li>Avoid race conditions with refresh tokens and active sessions</li>
     * <li>Ensure atomicity: either everything commits or everything rolls back</li>
     * </ul>
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
