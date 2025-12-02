package com.lanny.spring_security_template.infrastructure.audit;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.time.Instant;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.MDC;

class LoggingAuditEventPublisherTest {

    private LoggingAuditEventPublisher publisher;
    private Logger mockLogger;

    @BeforeEach
    void setup() {
        mockLogger = mock(Logger.class);

        publisher = new LoggingAuditEventPublisher() {
            @Override
            protected Logger getLogger() {
                return mockLogger;
            }
        };

        MDC.clear();
    }

    // -------------------------------------------------------------------------------
    @Test
    @DisplayName("testShouldPublishAuditEvent_withAllFieldsCorrectlyLogged")
    void testShouldPublishAuditEvent_withAllFieldsCorrectlyLogged() {
        // Arrange
        Instant ts = Instant.parse("2024-01-01T10:00:00Z");
        MDC.put("correlationId", "abc-123");

        // Act
        publisher.publishAuthEvent("LOGIN_SUCCESS", "lanny", ts, "Unit test");

        // Assert
        verify(mockLogger).info(
                eq("[AUDIT] event={} user={} timestamp={} details={} correlationId={}"),
                eq("LOGIN_SUCCESS"),
                eq("lanny"),
                eq(ts),
                eq("Unit test"),
                eq("abc-123"));
    }

    // -------------------------------------------------------------------------------
    @Test
    @DisplayName("testShouldSanitizeNullValues_whenArgumentsAreMissing")
    void testShouldSanitizeNullValues_whenArgumentsAreMissing() {

        publisher.publishAuthEvent("LOGIN_FAILURE", null, null, null);

        verify(mockLogger).info(
                eq("[AUDIT] event={} user={} timestamp={} details={} correlationId={}"),
                eq("LOGIN_FAILURE"),
                eq("anonymous"),
                any(Instant.class),
                eq("-"),
                eq("-"));
    }

    // -------------------------------------------------------------------------------
    @Test
    @DisplayName("testShouldIncludeCorrelationId_fromMDCWhenAvailable")
    void testShouldIncludeCorrelationId_fromMDCWhenAvailable() {
        // Arrange
        MDC.put("correlationId", "CID-999");

        // Act
        publisher.publishAuthEvent("LOGIN_ATTEMPT", "john", Instant.now(), "Testing CID");

        // Assert
        verify(mockLogger).info(
                eq("[AUDIT] event={} user={} timestamp={} details={} correlationId={}"),
                eq("LOGIN_ATTEMPT"),
                eq("john"),
                any(Instant.class),
                eq("Testing CID"),
                eq("CID-999"));
    }
}
