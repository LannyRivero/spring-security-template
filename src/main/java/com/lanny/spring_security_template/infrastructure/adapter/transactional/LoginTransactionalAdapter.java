package com.lanny.spring_security_template.infrastructure.adapter.transactional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.port.out.LoginPort;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.service.LoginService;

import lombok.RequiredArgsConstructor;

/**
 * Transactional adapter for the login use case.
 *
 * <p>
 * This adapter defines an explicit and independent transactional boundary
 * around the login flow.
 * </p>
 *
 * <p>
 * Security rationale:
 * </p>
 * <ul>
 * <li>Ensure atomic creation of refresh tokens and session state</li>
 * <li>Prevent partial login side effects</li>
 * <li>Isolate login execution from external transactional contexts</li>
 * </ul>
 *
 * <p>
 * The use of {@code Propagation.REQUIRES_NEW} ensures that the login process
 * is always executed in a dedicated transaction, even if an outer transaction
 * exists.
 * </p>
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
