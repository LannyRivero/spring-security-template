package com.lanny.spring_security_template.infrastructure.aop;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.audit.AuditEvent;
import com.lanny.spring_security_template.application.auth.audit.AuditReason;
import com.lanny.spring_security_template.application.auth.audit.Auditable;

/**
 * SecurityAuditAspect
 *
 * Banking-grade audit aspect.
 *
 * Responsibilities:
 * - Emit structured security audit events for explicitly annotated use cases
 * - Never infer events from method names
 * - Never log free-text exception messages
 *
 * Scope:
 * - Application-layer use cases annotated with @Auditable
 * - HTTP-bound by design (relies on MDC population upstream)
 */
@Aspect
@Component
public class SecurityAuditAspect {

    private static final Logger AUDIT_LOG = LoggerFactory.getLogger("SECURITY_AUDIT");

    // ==========
    // SUCCESS
    // ==========

    @AfterReturning(pointcut = "@annotation(auditable)")
    public void auditSuccess(
            JoinPoint joinPoint,
            Auditable auditable) {
        publish(
                auditable.event(),
                AuditReason.SUCCESS);
    }

    // ==========
    // FAILURE
    // ==========

    @AfterThrowing(pointcut = "@annotation(auditable)", throwing = "ex")
    public void auditFailure(
            JoinPoint joinPoint,
            Auditable auditable,
            Exception ex) {
        publish(
                auditable.event(),
                mapExceptionToReason(ex));
    }

    // ==========
    // INTERNALS
    // ==========

    private void publish(
            AuditEvent event,
            AuditReason reason) {
        String username = resolveUsername();
        String correlationId = MDC.get("correlationId");
        String path = MDC.get("requestPath");

        AUDIT_LOG.info(
                "event={} reason={} user={} path={} correlationId={}",
                event,
                reason,
                username,
                path,
                correlationId);
    }

    /**
     * Maps technical exceptions to controlled audit reasons.
     *
     * IMPORTANT:
     * - Never log raw exception messages
     * - Reasons must be finite and auditable
     */
    private AuditReason mapExceptionToReason(Exception ex) {
        if (ex instanceof BadCredentialsException) {
            return AuditReason.INVALID_CREDENTIALS;
        }
        if (ex instanceof AccessDeniedException) {
            return AuditReason.ACCESS_DENIED;
        }
        return AuditReason.UNKNOWN_FAILURE;
    }

    /**
     * Resolves the audited username.
     *
     * Banking rule:
     * - Security audit must never rely on request parameters
     * - Username must be propagated explicitly (e.g. via MDC)
     *
     * If missing, "anonymous" is used.
     */
    private String resolveUsername() {
        String username = MDC.get("username");
        return (username != null && !username.isBlank())
                ? username
                : "anonymous";
    }
}
