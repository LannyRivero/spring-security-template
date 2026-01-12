package com.lanny.spring_security_template.infrastructure.adapter.transactional;

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
 * This adapter exists exclusively for development and demo environments.
 * Its purpose is to provide a transactional boundary around the
 * application-layer {@link DevRegisterService}, which must remain pure
 * and free of Spring infrastructure concerns.
 * </p>
 *
 * <p>
 * This adapter must <strong>never</strong> be enabled in production
 * environments.
 * In production, all user registration flows are expected to be controlled,
 * audited, and explicitly designed for security and compliance.
 * </p>
 *
 * <p>
 * The absence of this adapter in production profiles is an intentional
 * security decision.
 * </p>
 */

@Service
@Profile({ "dev", "demo" })
@RequiredArgsConstructor
public class DevRegisterTransactionalAdapter implements DevRegisterPort {

    private final DevRegisterService delegate;

    /**
     * Executes a development-only registration command inside
     * a transactional boundary.
     *
     * <p>
     * This method is intended solely for non-production environments
     * to simplify development and demonstration workflows.
     * </p>
     */

    @Transactional
    public void register(RegisterCommand cmd) {
        delegate.register(cmd);
    }
}
