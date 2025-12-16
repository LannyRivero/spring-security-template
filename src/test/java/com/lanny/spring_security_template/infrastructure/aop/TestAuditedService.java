package com.lanny.spring_security_template.infrastructure.aop;

import org.springframework.stereotype.Service;

import com.lanny.spring_security_template.application.auth.audit.AuditEvent;
import com.lanny.spring_security_template.application.auth.audit.Auditable;

@Service
class TestAuditedService {

    @Auditable(event = AuditEvent.AUTH_LOGIN)
    public void success() {
    }

    @Auditable(event = AuditEvent.AUTH_LOGIN)
    public void failure() {
        throw new RuntimeException("SENSITIVE_MESSAGE_SHOULD_NOT_APPEAR");
    }
}
