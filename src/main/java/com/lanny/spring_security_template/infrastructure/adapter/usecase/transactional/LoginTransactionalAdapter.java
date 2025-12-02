package com.lanny.spring_security_template.infrastructure.adapter.usecase.transactional;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.service.LoginService;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class LoginTransactionalAdapter {

    private final LoginService loginService;

    @Transactional
    public JwtResult login(LoginCommand cmd) {
        return loginService.login(cmd);
    }
}
