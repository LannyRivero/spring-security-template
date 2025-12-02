package com.lanny.spring_security_template.infrastructure.adapter.usecase.transactional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.lanny.spring_security_template.application.auth.service.ChangePasswordService;

import lombok.RequiredArgsConstructor;

/**
 * Infrastructure-level transactional wrapper for ChangePasswordService.
 *
 * This adapter ensures:
 * - Spring controls the transaction boundary
 * - Application layer remains technology-agnostic (no @Transactional in
 * application)
 * - Clean separation between domain logic and persistence concerns
 */
@Service
@RequiredArgsConstructor
public class ChangePasswordTransactionalAdapter {

    private final ChangePasswordService delegate;

    /**
     * Changes a user's password with a properly managed transactional boundary.
     *
     * @param username        target username
     * @param currentPassword current password (for verification)
     * @param newPassword     new password to set
     */
    @Transactional
    public void changePassword(String username, String currentPassword, String newPassword) {
        delegate.changePassword(username, currentPassword, newPassword);
    }
}
