package com.lanny.spring_security_template.infrastructure.adapter.transactional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.port.out.RefreshPort;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.service.RefreshService;

import lombok.RequiredArgsConstructor;

/**
 * Transactional adapter for the refresh token rotation use case.
 *
 * <p>
 * This adapter defines an explicit and independent transactional boundary
 * around the refresh flow to ensure secure and atomic token rotation.
 * </p>
 *
 * <p>
 * Security rationale:
 * </p>
 * <ul>
 * <li>Execute refresh in a dedicated transaction via
 * {@code Propagation.REQUIRES_NEW}</li>
 * <li>Reduce race conditions during rotation using a strong isolation
 * level</li>
 * <li>Ensure atomic rotation: revoke the old token and issue a new token</li>
 * </ul>
 *
 * <p>
 * Note: refresh token reuse protection is primarily enforced by the configured
 * refresh token consumption engine (e.g. Redis atomic consume), while the
 * transactional boundary guarantees consistent persistence of rotation side
 * effects.
 * </p>
 */

@Service
@RequiredArgsConstructor
public class RefreshTransactionalAdapter implements RefreshPort {

    private final RefreshService refreshService;

    @Transactional(propagation = Propagation.REQUIRES_NEW, isolation = Isolation.REPEATABLE_READ)
    public JwtResult refresh(RefreshCommand cmd) {
        return refreshService.refresh(cmd);
    }
}
