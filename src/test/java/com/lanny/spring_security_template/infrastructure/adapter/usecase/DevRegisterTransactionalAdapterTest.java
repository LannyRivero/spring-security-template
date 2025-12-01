package com.lanny.spring_security_template.infrastructure.adapter.usecase;

import com.lanny.spring_security_template.application.auth.command.RegisterCommand;
import com.lanny.spring_security_template.application.auth.service.DevRegisterService;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;

import static org.mockito.Mockito.*;

class DevRegisterTransactionalAdapterTest {

    @Test
    @DisplayName("Should delegate register() call to DevRegisterService")
    void testShouldRegisterDelegatesToDevService() {
        // Arrange
        DevRegisterService service = mock(DevRegisterService.class);
        DevRegisterTransactionalAdapter adapter =
                new DevRegisterTransactionalAdapter(service);

        RegisterCommand cmd = new RegisterCommand(
                "newuser",
                "newuser@example.com",
                "StrongPass123!",   
                List.of("USER"),    
                List.of()           
        );

        // Act
        adapter.register(cmd);

        // Assert
        ArgumentCaptor<RegisterCommand> captor = ArgumentCaptor.forClass(RegisterCommand.class);
        verify(service, times(1)).register(captor.capture());

        RegisterCommand captured = captor.getValue();
        assert captured.username().equals("newuser");
        assert captured.email().equals("newuser@example.com");
        assert captured.rawPassword().equals("StrongPass123!");
        assert captured.roles().equals(List.of("USER"));
        assert captured.scopes().isEmpty();
    }

    @Test
    @DisplayName("Should propagate exception thrown by DevRegisterService")
    void testShouldRegisterPropagatesException() {
        // Arrange
        DevRegisterService service = mock(DevRegisterService.class);
        DevRegisterTransactionalAdapter adapter =
                new DevRegisterTransactionalAdapter(service);

        RegisterCommand cmd = new RegisterCommand(
                "failuser",
                "fail@example.com",
                "Pass123!",
                List.of("USER"),
                List.of()
        );

        doThrow(new IllegalStateException("boom"))
                .when(service)
                .register(any());

        // Act + Assert
        try {
            adapter.register(cmd);
            assert false : "Expected exception not thrown";
        } catch (IllegalStateException ex) {
            assert ex.getMessage().equals("boom");
        }

        verify(service, times(1)).register(cmd);
    }
}

