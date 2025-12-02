package com.lanny.spring_security_template.infrastructure.audit;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;

import lombok.extern.slf4j.Slf4j;

/**
 * {@code LoggingAuditEventPublisher} is the default infrastructure-level
 * implementation of {@link AuditEventPublisher}, responsible for publishing
 * authentication and authorization audit events via SLF4J logging.
 *
 * <p>
 * This adapter is designed for:
 * <ul>
 * <li>Development and testing environments</li>
 * <li>Production fallback when no external audit pipeline is configured</li>
 * </ul>
 * </p>
 *
 * <p>
 * Characteristics:
 * <ul>
 * <li>Stateless and thread-safe</li>
 * <li>Automatically enriches audit logs with Correlation ID via MDC</li>
 * <li>Safe handling of {@code null} and empty input fields</li>
 * </ul>
 * </p>
 *
 * <p>
 * For enterprise deployments, this class can be replaced with adapters such as:
 * <ul>
 * <li>KafkaAuditEventPublisher</li>
 * <li>ElasticsearchAuditEventPublisher</li>
 * <li>DatabaseAuditEventPublisher</li>
 * </ul>
 * without affecting application-layer logic.
 * </p>
 */
@Slf4j
@Component
public class LoggingAuditEventPublisher implements AuditEventPublisher {

    /**
     * Allows overriding the logger in tests, since SLF4J static loggers
     * cannot be easily mocked.
     *
     * @return the logger instance used for publishing audit logs
     */
    protected Logger getLogger() {
        return log;
    }

    /**
     * Publishes an authentication-related audit event.
     *
     * <p>
     * Ensures that all inputs are safely normalized before logging,
     * preventing null pointer issues and guaranteeing consistent output.
     * </p>
     *
     * @param eventType type of audit event (e.g. LOGIN_SUCCESS, LOGIN_FAILURE)
     * @param username  username involved in the event, may be null
     * @param timestamp event timestamp; if null, a new {@link Instant} is generated
     * @param details   additional contextual information, may be null
     */
    @Override
    public void publishAuthEvent(String eventType, String username, Instant timestamp, String details) {

        String safeUser = sanitize(username, "anonymous");
        String safeDetails = sanitize(details, "-");
        String correlationId = sanitize(MDC.get("correlationId"), "-");
        String clientIp = sanitize(MDC.get("clientIp"), "-");
        String userAgent = sanitize(MDC.get("userAgent"), "-");

        getLogger().info(
                "[AUDIT] event={} user={} timestamp={} details={} correlationId={} ip={} agent={}",
                eventType,
                safeUser,
                (timestamp != null ? timestamp : Instant.now()),
                safeDetails,
                correlationId,
                clientIp,
                userAgent);
    }

    private String sanitize(String input, String fallback) {
        if (input == null || input.isBlank())
            return fallback;
        return input.replaceAll("[\\n\\r\t]", "_").trim();
    }

}
