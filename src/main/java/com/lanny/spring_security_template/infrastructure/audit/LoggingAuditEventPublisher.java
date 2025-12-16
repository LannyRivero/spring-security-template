package com.lanny.spring_security_template.infrastructure.audit;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;
import com.lanny.spring_security_template.domain.time.ClockProvider;

import lombok.extern.slf4j.Slf4j;

/**
 * Default logging-based implementation of {@link AuditEventPublisher}.
 *
 * <p>
 * Acts as:
 * <ul>
 * <li>Primary audit publisher for dev/test</li>
 * <li>Safe fallback for production when no external audit sink is
 * configured</li>
 * </ul>
 *
 * <p>
 * Banking-grade guarantees:
 * <ul>
 * <li>No PII leakage</li>
 * <li>No free-text exception messages</li>
 * <li>Deterministic timestamps via ClockProvider</li>
 * <li>Structured, SIEM-friendly logs</li>
 * </ul>
 */
@Slf4j
@Component
public class LoggingAuditEventPublisher implements AuditEventPublisher {

    private final ClockProvider clock;

    public LoggingAuditEventPublisher(ClockProvider clock) {
        this.clock = clock;
    }

    /**
     * Allows overriding the logger in tests.
     */
    protected Logger getLogger() {
        return log;
    }

    @Override
    public void publishAuthEvent(
            String eventType,
            String username,
            Instant timestamp,
            String details) {

        String safeUser = sanitize(username, "anonymous");
        String safeDetails = sanitize(details, "-");

        String correlationId = sanitize(MDC.get("correlationId"), "-");
        String clientIp = sanitize(MDC.get("clientIp"), "-");
        String userAgent = sanitize(MDC.get("userAgent"), "-");

        Instant eventTime = (timestamp != null)
                ? timestamp
                : clock.now();

        getLogger().info(
                "[AUDIT] event={} user={} timestamp={} details={} correlationId={} ip={} agent={}",
                eventType,
                safeUser,
                eventTime,
                safeDetails,
                correlationId,
                clientIp,
                userAgent);
    }

    /**
     * Normalizes audit fields to prevent log injection
     * and ensure consistent output.
     */
    private String sanitize(String input, String fallback) {
        if (input == null || input.isBlank()) {
            return fallback;
        }
        return input.replaceAll("[\\n\\r\\t]", "_").trim();
    }
}
