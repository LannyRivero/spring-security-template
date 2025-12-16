package com.lanny.spring_security_template.infrastructure.adapter.usecase.transactional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.port.out.LoginPort;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.service.LoginService;

import lombok.RequiredArgsConstructor;
/**
 * Transactional adapter fot login use case
 * 
 * -Independent transaction boundary
 * Atomic istence of refresh token and session state
 * -No propagation of external transactions
 * 
 */

@Service
@RequiredArgsConstructor
public class LoginTransactionalAdapter implements LoginPort {

    private final LoginService loginService;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public JwtResult login(LoginCommand cmd) {
        return loginService.login(cmd);
    }
}
