package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Main orchestrator for user login.
 * Delegates validation, token creation and metrics to specialized services.
 */
@Service
@RequiredArgsConstructor
public class LoginService {

    private final AuthenticationValidator validator;
    private final TokenSessionCreator tokenCreator;
    private final LoginMetricsRecorder metrics;

    public JwtResult login(LoginCommand cmd) {
        try {
            var user = validator.validate(cmd);
            JwtResult result = tokenCreator.create(user.username().value());
            metrics.recordSuccess();
            return result;
        } catch (InvalidCredentialsException | UsernameNotFoundException e) {
            metrics.recordFailure();
            throw e;
        }
    }
}
