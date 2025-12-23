package com.lanny.spring_security_template.infrastructure.aop;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.audit.AuditEvent;
import com.lanny.spring_security_template.application.auth.audit.AuditReason;
import com.lanny.spring_security_template.application.auth.audit.Auditable;

import static com.lanny.spring_security_template.infrastructure.observability.MdcKeys.*;

/**
 * {@code SecurityAuditAspect}
 *
 * <p>
 * Banking-grade security audit aspect.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 *   <li>Emit structured security audit events for explicitly annotated use cases</li>
 *   <li>Never infer events from method names</li>
 *   <li>Never log free-text exception messages</li>
 * </ul>
 *
 * <h2>Scope</h2>
 * <ul>
 *   <li>Application-layer use cases annotated with {@link Auditable}</li>
 *   <li>HTTP-bound execution relying on MDC context populated by filters</li>
 * </ul>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 *   <li>Finite, auditable reasons only</li>
 *   <li>No PII leakage</li>
 *   <li>Correlation-safe logging</li>
 * </ul>
 */
@Aspect
@Component
public class SecurityAuditAspect {

    private static final Logger AUDIT_LOG =
            LoggerFactory.getLogger("SECURITY_AUDIT");

    // ==========
    // SUCCESS
    // ==========

    @AfterReturning(pointcut = "@annotation(auditable)")
    public void auditSuccess(
            JoinPoint joinPoint,
            Auditable auditable) {

        publish(auditable.event(), AuditReason.SUCCESS);
    }

    // ==========
    // FAILURE
    // ==========

    @AfterThrowing(pointcut = "@annotation(auditable)", throwing = "ex")
    public void auditFailure(
            JoinPoint joinPoint,
            Auditable auditable,
            Exception ex) {

        publish(auditable.event(), mapExceptionToReason(ex));
    }

    // ==========
    // INTERNALS
    // ==========

    private void publish(
            AuditEvent event,
            AuditReason reason) {

        String username = resolveUsername();
        String correlationId = MDC.get(CORRELATION_ID);
        String requestPath = MDC.get(REQUEST_PATH);

        if (reason == AuditReason.SUCCESS) {
            AUDIT_LOG.info(
                    "event={} reason={} user={} path={} correlationId={}",
                    event, reason, username, requestPath, correlationId
            );
        } else {
            AUDIT_LOG.warn(
                    "event={} reason={} user={} path={} correlationId={}",
                    event, reason, username, requestPath, correlationId
            );
        }
    }

    /**
     * Maps technical exceptions to controlled audit reasons.
     *
     * <p>
     * IMPORTANT:
     * </p>
     * <ul>
     *   <li>Never log raw exception messages</li>
     *   <li>Reasons must be finite and auditable</li>
     * </ul>
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
     * <p>
     * Banking rule:
     * </p>
     * <ul>
     *   <li>Audit must never rely on request parameters</li>
     *   <li>Username must be propagated explicitly via MDC</li>
     * </ul>
     *
     * <p>
     * If missing, {@code anonymous} is used.
     * </p>
     */
    private String resolveUsername() {
        String username = MDC.get(USERNAME);
        return (username != null && !username.isBlank())
                ? username
                : "anonymous";
    }
}

