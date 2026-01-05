package com.lanny.spring_security_template.infrastructure.transactional;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.lanny.spring_security_template.application.auth.command.RegisterCommand;
import com.lanny.spring_security_template.application.auth.port.out.DevRegisterPort;
import com.lanny.spring_security_template.application.auth.service.DevRegisterService;

import lombok.RequiredArgsConstructor;

/**
 * Transactional adapter for DevRegisterService.
 *
 * <p>
 * This adapter exists only for development/demo environments.
 * Its purpose is to provide a transactional boundary around the
 * application-layer DevRegisterService, which must remain pure
 * and free of Spring infrastructure concerns.
 * </p>
 *
 * <p>
 * In production this bean is not loaded, ensuring that
 * development-only registration flows cannot be used.
 * </p>
 */
@Service
@Profile({ "dev", "demo" })
@RequiredArgsConstructor
public class DevRegisterTransactionalAdapter implements DevRegisterPort {

    private final DevRegisterService delegate;

    /**
     * Executes the register command inside a transactional boundary.
     */
    @Transactional
    public void register(RegisterCommand cmd) {
        delegate.register(cmd);
    }
}
