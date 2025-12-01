package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.command.RegisterCommand;
import com.lanny.spring_security_template.application.auth.port.in.AuthUseCase;
import com.lanny.spring_security_template.application.auth.query.MeQuery;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.result.MeResult;

import com.lanny.spring_security_template.infrastructure.adapter.usecase.ChangePasswordTransactionalAdapter;
import com.lanny.spring_security_template.infrastructure.adapter.usecase.DevRegisterTransactionalAdapter;
import com.lanny.spring_security_template.infrastructure.adapter.usecase.LoginTransactionalAdapter;
import com.lanny.spring_security_template.infrastructure.adapter.usecase.RefreshTransactionalAdapter;

import lombok.RequiredArgsConstructor;

/**
 * Core implementation of AuthUseCase.
 *
 * Pure orchestration. No logging, no MDC, no Spring, no cross-cutting concerns.
 */
@RequiredArgsConstructor
public class AuthUseCaseImpl implements AuthUseCase {

    private final LoginTransactionalAdapter loginAdapter;
    private final RefreshTransactionalAdapter refreshAdapter;
    private final MeService meService;
    private final DevRegisterTransactionalAdapter devRegisterAdapter;
    private final ChangePasswordTransactionalAdapter changePasswordAdapter;

    @Override
    public JwtResult login(LoginCommand cmd) {
        validateInput(cmd.username(), cmd.password());
        return loginAdapter.login(cmd);
    }

    @Override
    public JwtResult refresh(RefreshCommand cmd) {
        return refreshAdapter.refresh(cmd);
    }

    @Override
    public MeResult me(MeQuery query) {
        return meService.me(query.username());
    }

    @Override
    public void registerDev(RegisterCommand cmd) {
        devRegisterAdapter.register(cmd);
    }

    @Override
    public void changePassword(String username, String oldPassword, String newPassword) {
        changePasswordAdapter.changePassword(username, oldPassword, newPassword);
    }

    private void validateInput(String username, String password) {
        if (username == null || username.isBlank() ||
                password == null || password.isBlank()) {
            throw new IllegalArgumentException("Username and password must not be blank");
        }
    }
}
