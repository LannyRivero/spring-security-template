package com.lanny.spring_security_template.infrastructure.config;

import com.lanny.spring_security_template.application.auth.port.in.AuthUseCase;
import com.lanny.spring_security_template.application.auth.service.*;
import com.lanny.spring_security_template.infrastructure.adapter.usecase.*;
import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;
import com.lanny.spring_security_template.domain.time.ClockProvider;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.assertj.core.api.Assertions.assertThat;

class AuthUseCaseConfigTest {

    private final AuthUseCaseConfig config = new AuthUseCaseConfig();

    @Test
    @DisplayName("testShouldCreateCoreAuthUseCase")
    void testShouldCreateCoreAuthUseCase() {
        LoginTransactionalAdapter loginAdapter = Mockito.mock(LoginTransactionalAdapter.class);
        RefreshTransactionalAdapter refreshAdapter = Mockito.mock(RefreshTransactionalAdapter.class);
        MeService meService = Mockito.mock(MeService.class);
        DevRegisterTransactionalAdapter devRegister = Mockito.mock(DevRegisterTransactionalAdapter.class);
        ChangePasswordTransactionalAdapter changePwd = Mockito.mock(ChangePasswordTransactionalAdapter.class);

        AuthUseCase core = config.authUseCaseCore(
                loginAdapter, refreshAdapter, meService, devRegister, changePwd);

        assertThat(core)
                .isInstanceOf(AuthUseCaseImpl.class)
                .isNotNull();
    }

    @Test
    @DisplayName("testShouldWrapCoreAuthUseCaseWithLoggingDecorator")
    void testShouldWrapCoreAuthUseCaseWithLoggingDecorator() {
        AuthUseCase core = Mockito.mock(AuthUseCase.class);
        AuditEventPublisher audit = Mockito.mock(AuditEventPublisher.class);
        ClockProvider clock = Mockito.mock(ClockProvider.class);

        AuthUseCase decorated = config.authUseCase(core, audit, clock);

        assertThat(decorated)
                .isInstanceOf(AuthUseCaseLoggingDecorator.class)
                .isNotNull();
    }
}
