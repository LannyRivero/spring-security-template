package com.lanny.spring_security_template.infrastructure.observability;

/**
 * Centralized MDC keys contract.
 *
 * <p>
 * All filters, aspects and loggers MUST use these constants.
 * This guarantees consistent audit and observability data.
 * </p>
 */
public final class MdcKeys {

    private MdcKeys() {
    }

    public static final String CORRELATION_ID = "correlationId";
    public static final String REQUEST_PATH = "requestPath";
    public static final String USERNAME = "username";
    public static final String CLIENT_IP = "clientIp";
}
