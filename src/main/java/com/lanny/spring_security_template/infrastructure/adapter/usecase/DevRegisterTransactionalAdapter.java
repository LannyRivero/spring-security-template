package com.lanny.spring_security_template.infrastructure.adapter.usecase;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.lanny.spring_security_template.application.auth.command.RegisterCommand;
import com.lanny.spring_security_template.application.auth.service.DevRegisterService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class DevRegisterTransactionalAdapter {

    private final DevRegisterService delegate;

    @Transactional
    public void register(RegisterCommand cmd) {
        delegate.register(cmd);
    }
}
