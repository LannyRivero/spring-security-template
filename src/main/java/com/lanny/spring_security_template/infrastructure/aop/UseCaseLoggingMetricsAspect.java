package com.lanny.spring_security_template.infrastructure.aop;

import static com.lanny.spring_security_template.infrastructure.observability.MdcKeys.*;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;

/**
 * {@code UseCaseLoggingMetricsAspect}
 *
 * <p>
 * Cross-cutting logging and metrics for application-layer use cases.
 * </p>
 *
 * <h2>Scope</h2>
 * <ul>
 * <li>Application-layer use cases only ({@code application..service..*})</li>
 * <li>No interception of domain, infrastructure, or web layers</li>
 * </ul>
 *
 * <h2>Metrics</h2>
 * <ul>
 * <li>{@code usecase_calls_total}</li>
 * <li>{@code usecase_duration_seconds}</li>
 * </ul>
 *
 * <h2>Logging</h2>
 * <ul>
 * <li>{@code DEBUG} level for successful executions</li>
 * <li>{@code WARN} level for failed executions</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>No method arguments are logged (PII-safe)</li>
 * <li>Metric cardinality is strictly controlled</li>
 * <li>Fully infrastructure-level (no coupling with application code)</li>
 * </ul>
 *
 * <p>
 * This aspect provides <strong>operational observability only</strong>.
 * It must not be confused with security audit logging, which is handled
 * separately by dedicated security audit components.
 * </p>
 */
@Aspect
@Component
@Order(100)
@Slf4j
public class UseCaseLoggingMetricsAspect {

        private final MeterRegistry meterRegistry;

        public UseCaseLoggingMetricsAspect(MeterRegistry meterRegistry) {
                this.meterRegistry = meterRegistry;
        }

        @Around("execution(public * com.lanny.spring_security_template.application..service..*(..))")
        public Object measureUseCase(ProceedingJoinPoint pjp) throws Throwable {

                String useCase = pjp.getSignature()
                                .getDeclaringType()
                                .getSimpleName();

                String user = MDC.get(USERNAME);
                if (user == null || user.isBlank()) {
                        user = "anonymous";
                }

                String correlationId = MDC.get(CORRELATION_ID);

                Timer.Sample sample = Timer.start(meterRegistry);

                try {
                        Object result = pjp.proceed();

                        sample.stop(
                                        Timer.builder("usecase_duration_seconds")
                                                        .tag("usecase", useCase)
                                                        .tag("status", "SUCCESS")
                                                        .register(meterRegistry));

                        meterRegistry.counter(
                                        "usecase_calls_total",
                                        "usecase", useCase,
                                        "status", "SUCCESS").increment();

                        log.debug(
                                        "[USECASE_SUCCESS] usecase={} user={} correlationId={}",
                                        useCase, user, correlationId);

                        return result;

                } catch (Throwable ex) {

                        sample.stop(
                                        Timer.builder("usecase_duration_seconds")
                                                        .tag("usecase", useCase)
                                                        .tag("status", "ERROR")
                                                        .register(meterRegistry));

                        meterRegistry.counter(
                                        "usecase_calls_total",
                                        "usecase", useCase,
                                        "status", "ERROR").increment();

                        log.warn(
                                        "[USECASE_FAILURE] usecase={} user={} correlationId={}",
                                        useCase, user, correlationId);

                        throw ex;
                }
        }
}
