package com.lanny.spring_security_template.infrastructure.adapter.usecase.transactional;

import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.service.RefreshService;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class RefreshTransactionalAdapterTest {

    @Mock
    private RefreshService refreshService;

    @InjectMocks
    private RefreshTransactionalAdapter adapter;

    @Test
    @DisplayName("Should delegate refresh command to RefreshService")
    void testShouldDelegateRefresh() {
        RefreshCommand cmd = new RefreshCommand("refresh-token");

        JwtResult result = mock(JwtResult.class);
        when(refreshService.refresh(cmd)).thenReturn(result);

        JwtResult returned = adapter.refresh(cmd);

        verify(refreshService).refresh(cmd);
        assert returned == result;
    }

    @Test
    @DisplayName("Should propagate exception thrown by RefreshService")
    void testShouldPropagateException() {
        RefreshCommand cmd = new RefreshCommand("invalid-refresh-token");

        when(refreshService.refresh(cmd))
                .thenThrow(new IllegalStateException("invalid refresh token"));

        assertThatThrownBy(() -> adapter.refresh(cmd))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("invalid refresh token");

        verify(refreshService).refresh(cmd);
    }
}

