package com.lanny.spring_security_template.infrastructure.adapter.usecase.transactional;

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
 * Transactional adapter for Refresh token rotation
 * 
 * -Independent transaction(REQUIRE_NEW)
 * -Strong isolation to prevent token reuse races
 * -Atomic rotation: revoke old token + issue new token
 */

@Service
@RequiredArgsConstructor
public class RefreshTransactionalAdapter implements RefreshPort {

    private final RefreshService refreshService;

    @Transactional(
        propagation = Propagation.REQUIRES_NEW,
        isolation = Isolation.REPEATABLE_READ
    )
    public JwtResult refresh(RefreshCommand cmd) {
        return refreshService.refresh(cmd);
    }
}
