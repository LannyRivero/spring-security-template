package com.lanny.spring_security_template.infrastructure.adapter.usecase.transactional;

import com.lanny.spring_security_template.application.auth.command.RegisterCommand;
import com.lanny.spring_security_template.application.auth.port.out.DevRegisterPort;

/**
 * Null Object for DevRegisterPort.
 *
 * Used in production to explicitly disable dev-only registration.
 */
public class NoOpDevRegisterAdapter implements DevRegisterPort {

    @Override
    public void register(RegisterCommand command) {
        throw new UnsupportedOperationException(
            "User registration is disabled in production environments"
        );
    }
}

