package com.lanny.spring_security_template.application.auth.port.out;

import java.time.Instant;

/**
 * Ounbound port for publishing authentication and security-related audit
 * events.
 * 
 * <p>
 * This abstraction decouples the application layer from specific infrastructure
 * mechanisms such as Kafka, database tables, or file-based logging.
 * </p>
 * 
 * <p>
 * <strong>Purpose:</strong>
 * </p>
 * <ul>
 * <li>Provide traceability og authentication-related operations.</li>
 * <li>Feed security dashboard or SIEM systems(e.g., Splunk, Loki, ELK).</li>
 * <li>Enable compliance with audict requirements(ISO 27001, SOC2)</li>
 * </ul>
 * 
 * <p>
 * The default implementation may simply log eventsto the application logger,
 * but production adapters can push them to Kafka, an audit >DB or an external
 * monitoring system.
 * </p>
 */

public interface AuditEventPublisher {
    /**
     * Publishes an audit event to the configured channel.
     *
     * @param eventType short event identifier (e.g., "USER_LOGGED_IN",
     *                  "TOKEN_REVOKED")
     * @param username  username or principal associated with the event
     * @param timestamp time of the event occurrence (UTC)
     * @param details   optional structured description or metadata (IP, user-agent,
     *                  etc.)
     */
    void publishAuthEvent(String eventType, String username, Instant timestamp, String details);
}
