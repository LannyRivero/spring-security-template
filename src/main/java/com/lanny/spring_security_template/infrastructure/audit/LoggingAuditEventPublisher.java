package com.lanny.spring_security_template.infrastructure.audit;

import java.time.Instant;

import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;

import lombok.extern.slf4j.Slf4j;

/**
 * Default in-memory / console implementation of {@link AuditEventPublisher}.
 *
 * <p>
 * Publishes audit events to the application logs using SLF4J.
 * This implementation is stateless and suitable for development
 * and testing environments.
 * </p>
 *
 * <p>
 * Production adapters can extend this to push events to Kafka,
 * Elasticsearch, or a dedicated audit database.
 * </p>
 */
@Slf4j
@Component
public class LoggingAuditEventPublisher implements AuditEventPublisher {

    @Override
    public void publishAuthEvent(String eventType, String username, Instant timestamp, String details) {
        log.info("[AUDIT] event={} user={} timestamp={} details={}",
                eventType, username, timestamp, details != null ? details : "-");
    }
}
