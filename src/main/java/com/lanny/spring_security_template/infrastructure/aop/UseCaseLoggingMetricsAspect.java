package com.lanny.spring_security_template.infrastructure.aop;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * UseCaseLoggingMetricsAspect
 *
 * Cross-cutting logging + metrics for application-layer use cases.
 *
 * Scope:
 * - ONLY application use cases (application..service..*)
 *
 * Metrics:
 * - usecase_calls_total
 * - usecase_duration_seconds
 *
 * Logging:
 * - DEBUG for success
 * - WARN for failures
 *
 * Design notes:
 * - No arguments logged (PII-safe)
 * - Cardinality controlled (finite tag set)
 * - Fully infrastructure-level (no app coupling)
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

                String useCase = pjp.getSignature().getDeclaringType().getSimpleName();

                String user = MDC.get("username");
                if (user == null || user.isBlank()) {
                        user = "anonymous";
                }

                String correlationId = MDC.get("correlationId");

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
