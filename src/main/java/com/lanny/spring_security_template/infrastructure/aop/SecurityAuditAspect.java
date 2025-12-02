package com.lanny.spring_security_template.infrastructure.aop;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;

/**
 * SecurityAuditAspect
 *
 * Responsabilidad:
 * - Registrar eventos de auditoría para operaciones sensibles:
 * * login / login fallido
 * * refresh de token
 * * cambio de contraseña
 * * registro de usuario (dev)
 *
 * - Emite logs estructurados en un logger dedicado "SECURITY_AUDIT"
 * para facilitar integraciones SIEM / log shipping.
 *
 * Si en el futuro quieres usar un AuditEventPublisher (puerto),
 * este aspecto se puede adaptar fácilmente para delegar ahí.
 */
@Slf4j
@Aspect
@Component
public class SecurityAuditAspect {

    private static final Logger AUDIT_LOG = LoggerFactory.getLogger("SECURITY_AUDIT");

    // Pointcut genérico: todos los métodos de servicios de auth
    @Pointcut("execution(public * com.lanny.spring_security_template.application.auth.service..*(..))")
    public void authServiceOperation() {
        // marker
    }

    // ==========
    // SUCCESS
    // ==========

    @AfterReturning("authServiceOperation()")
    public void auditSuccess(JoinPoint jp) {
        String methodName = jp.getSignature().getName().toLowerCase();

        String eventType = resolveEventType(methodName, true);
        if (eventType == null) {
            return; // otros métodos no se auditan
        }

        String username = resolveUsername();
        String correlationId = MDC.get("correlationId");
        String path = resolvePath();

        AUDIT_LOG.info("event={} outcome=SUCCESS user={} path={} correlationId={}",
                eventType, username, path, correlationId);
    }

    // ==========
    // FAILURE
    // ==========

    @AfterThrowing(pointcut = "authServiceOperation()", throwing = "ex")
    public void auditFailure(JoinPoint jp, Throwable ex) {
        String methodName = jp.getSignature().getName().toLowerCase();

        String eventType = resolveEventType(methodName, false);
        if (eventType == null) {
            return; // otros métodos no se auditan
        }

        String username = resolveUsername();
        String correlationId = MDC.get("correlationId");
        String path = resolvePath();

        AUDIT_LOG.warn("event={} outcome=FAILURE user={} path={} correlationId={} reason={}",
                eventType, username, path, correlationId, ex.getMessage());
    }

    // ==========
    // HELPERS
    // ==========

    /**
     * Mapea nombres de métodos a tipos de evento de auditoría.
     * Puedes ajustar estos nombres a tu gusto / estándar interno.
     */
    private String resolveEventType(String methodName, boolean success) {

        if (methodName.contains("login")) {
            return "AUTH_LOGIN";
        }
        if (methodName.contains("refresh")) {
            return "AUTH_TOKEN_REFRESH";
        }
        if (methodName.contains("changepassword") || methodName.contains("password")) {
            return "AUTH_PASSWORD_CHANGE";
        }
        if (methodName.contains("register") || methodName.contains("signup")) {
            return "AUTH_USER_REGISTER";
        }
        // otros métodos de auth no se auditan por defecto
        return null;
    }

    /**
     * Resolver usuario:
     * 1) Si hay Authentication en el SecurityContext → auth.getName()
     * 2) Si no, se intenta obtener "username" de la request (útil para login)
     * 3) Si falla, "anonymous"
     */
    private String resolveUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getName() != null) {
            return auth.getName();
        }

        HttpServletRequest req = currentRequest();
        if (req != null) {
            String username = req.getParameter("username");
            if (username != null && !username.isBlank()) {
                return username;
            }
        }
        return "anonymous";
    }

    private String resolvePath() {
        HttpServletRequest req = currentRequest();
        return (req != null) ? req.getRequestURI() : "N/A";
    }

    private HttpServletRequest currentRequest() {
        var attrs = RequestContextHolder.getRequestAttributes();
        if (attrs instanceof ServletRequestAttributes servletAttrs) {
            return servletAttrs.getRequest();
        }
        return null;
    }
}
