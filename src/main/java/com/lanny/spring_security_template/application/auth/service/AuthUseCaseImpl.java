package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.command.RegisterCommand;
import com.lanny.spring_security_template.application.auth.port.in.AuthUseCase;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.result.MeResult;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthUseCaseImpl implements AuthUseCase {

    private final LoginService loginService;
    private final RefreshService refreshService;
    private final MeService meService;
    private final DevRegisterService devRegisterService;

    @Override
    public JwtResult login(LoginCommand cmd) {
        return loginService.login(cmd);
    }

    @Override
    public JwtResult refresh(RefreshCommand cmd) {
        return refreshService.refresh(cmd);
    }

    @Override
    public MeResult me(String username) {
        return meService.me(username);
    }

    @Override
    public void registerDev(RegisterCommand cmd) {
        devRegisterService.register(cmd);
    }
}


