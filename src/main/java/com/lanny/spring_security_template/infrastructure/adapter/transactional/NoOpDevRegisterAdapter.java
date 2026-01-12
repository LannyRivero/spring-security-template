package com.lanny.spring_security_template.infrastructure.adapter.transactional;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import com.lanny.spring_security_template.application.auth.command.RegisterCommand;
import com.lanny.spring_security_template.application.auth.port.out.DevRegisterPort;

/**
 * Null Object implementation of {@link DevRegisterPort}.
 *
 * <p>
 * This adapter is used in production environments to explicitly disable
 * development-only user registration flows.
 * </p>
 *
 * <p>
 * Any attempt to invoke this adapter will fail immediately, ensuring that
 * dev-only registration cannot be accidentally exposed in production.
 * </p>
 */

@Service
@Profile("prod")
public class NoOpDevRegisterAdapter implements DevRegisterPort {

    @Override
    public void register(RegisterCommand command) {
        throw new UnsupportedOperationException(
                "User registration is disabled in production environments");
    }
}
