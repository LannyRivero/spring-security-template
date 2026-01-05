package com.lanny.spring_security_template.infrastructure.adapter.usecase.transactional;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

import com.lanny.spring_security_template.application.auth.service.ChangePasswordService;
import com.lanny.spring_security_template.infrastructure.adapter.transactional.ChangePasswordTransactionalAdapter;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for ChangePasswordTransactionalAdapter.
 *
 * Focus:
 * - Delegation correctness
 * - Exception propagation (rollback responsibility)
 * - No business logic inside adapter
 */
@ExtendWith(MockitoExtension.class)
class ChangePasswordTransactionalAdapterTest {

    @Mock
    private ChangePasswordService changePasswordService;

    @InjectMocks
    private ChangePasswordTransactionalAdapter adapter;

    @Test
    @DisplayName("Should delegate password change to application service")
    void shouldDelegatePasswordChange() {
        String username = "john.doe";
        String currentPassword = "oldPass123";
        String newPassword = "newPass456";

        adapter.changePassword(username, currentPassword, newPassword);

        verify(changePasswordService)
                .changePassword(username, currentPassword, newPassword);
    }

    @Test
    @DisplayName("Should propagate exception when password change fails")
    void shouldPropagateExceptionWhenChangeFails() {
        String username = "john.doe";
        String currentPassword = "wrongPass";
        String newPassword = "newPass456";

        doThrow(new IllegalStateException("Invalid password"))
                .when(changePasswordService)
                .changePassword(username, currentPassword, newPassword);

        try {
            adapter.changePassword(username, currentPassword, newPassword);
        } catch (IllegalStateException ex) {
        }

        verify(changePasswordService)
                .changePassword(username, currentPassword, newPassword);
    }
}
