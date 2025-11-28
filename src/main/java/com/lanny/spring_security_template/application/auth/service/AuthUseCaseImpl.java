package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.command.RegisterCommand;
import com.lanny.spring_security_template.application.auth.port.in.AuthUseCase;
import com.lanny.spring_security_template.application.auth.query.MeQuery;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.result.MeResult;

import lombok.RequiredArgsConstructor;

/**
 * Core implementation of AuthUseCase.
 *
 * Contains only orchestration logic. No logging, MDC, auditing
 * or any other cross-cutting concern.
 */
@RequiredArgsConstructor
public class AuthUseCaseImpl implements AuthUseCase {

    private final LoginService loginService;
    private final RefreshService refreshService;
    private final MeService meService;
    private final DevRegisterService devRegisterService;
    private final ChangePasswordService changePasswordService;

    @Override
    public JwtResult login(LoginCommand cmd) {
        validateInput(cmd.username(), cmd.password());
        return loginService.login(cmd);
    }

    @Override
    public JwtResult refresh(RefreshCommand cmd) {
        return refreshService.refresh(cmd);
    }

    @Override
    public MeResult me(MeQuery query) {
        return meService.me(query.username());
    }

    @Override
    public void registerDev(RegisterCommand cmd) {
        devRegisterService.register(cmd);
    }

    @Override
    public void changePassword(String username, String oldPassword, String newPassword) {
        changePasswordService.changePassword(username, oldPassword, newPassword);
    }

    private void validateInput(String username, String password) {
        if (username == null || username.isBlank() ||
                password == null || password.isBlank()) {
            throw new IllegalArgumentException("Username and password must not be blank");
        }
    }
}
