package com.lanny.spring_security_template.infrastructure.adapter.usecase.transactional;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.service.RefreshService;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class RefreshTransactionalAdapter {

    private final RefreshService refreshService;

    @Transactional
    public JwtResult refresh(RefreshCommand cmd) {
        return refreshService.refresh(cmd);
    }
}
