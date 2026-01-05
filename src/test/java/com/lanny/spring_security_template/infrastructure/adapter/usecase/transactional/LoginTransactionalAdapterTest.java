package com.lanny.spring_security_template.infrastructure.adapter.usecase.transactional;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.service.LoginService;
import com.lanny.spring_security_template.infrastructure.transactional.LoginTransactionalAdapter;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class LoginTransactionalAdapterTest {

    @Mock
    private LoginService loginService;

    @InjectMocks
    private LoginTransactionalAdapter adapter;

    @Test
    @DisplayName("Should delegate login command to LoginService")
    void testShouldDelegateLogin() {
        LoginCommand cmd = new LoginCommand("user", "password");

        JwtResult result = mock(JwtResult.class);
        when(loginService.login(cmd)).thenReturn(result);

        JwtResult returned = adapter.login(cmd);

        verify(loginService).login(cmd);
        assert returned == result;
    }

    @Test
    @DisplayName("Should propagate exception thrown by LoginService")
    void testShouldPropagateException() {
        LoginCommand cmd = new LoginCommand("user", "bad-password");

        when(loginService.login(cmd))
                .thenThrow(new IllegalStateException("invalid credentials"));

        assertThatThrownBy(() -> adapter.login(cmd))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("invalid credentials");

        verify(loginService).login(cmd);
    }
}

