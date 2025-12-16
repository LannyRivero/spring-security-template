package com.lanny.spring_security_template.infrastructure.adapter.usecase.transactional;

import com.lanny.spring_security_template.application.auth.command.RegisterCommand;
import com.lanny.spring_security_template.application.auth.service.DevRegisterService;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.doThrow;

import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(MockitoExtension.class)
class DevRegisterTransactionalAdapterTest {

    @Mock
    private DevRegisterService service;

    @InjectMocks
    private DevRegisterTransactionalAdapter adapter;

    @Test
    @DisplayName("Should delegate register command to DevRegisterService")
    void shouldDelegateRegisterCommand() {
        RegisterCommand cmd = new RegisterCommand(
                "newuser",
                "newuser@example.com",
                "StrongPass123!",
                List.of("USER"),
                List.of()
        );

        adapter.register(cmd);

        verify(service).register(cmd);
    }

    @Test
    @DisplayName("Should propagate exception thrown by DevRegisterService")
    void shouldPropagateException() {
        RegisterCommand cmd = new RegisterCommand(
                "failuser",
                "fail@example.com",
                "Pass123!",
                List.of("USER"),
                List.of()
        );

        doThrow(new IllegalStateException("boom"))
                .when(service)
                .register(cmd);

        assertThatThrownBy(() -> adapter.register(cmd))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("boom");

        verify(service).register(cmd);
    }
}


