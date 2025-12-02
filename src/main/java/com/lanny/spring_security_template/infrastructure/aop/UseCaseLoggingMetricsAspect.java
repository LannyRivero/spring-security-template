package com.lanny.spring_security_template.infrastructure.aop;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.*;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * UseCaseLoggingMetricsAspect
 *
 * Cross-cutting logging + metrics for application-layer use cases.
 *
 * - Applies to public methods in package:
 * com.lanny.spring_security_template.application.auth.service..*
 *
 * - Logs start/end with correlationId and basic context.
 * - Records Prometheus/Micrometer metrics:
 * - usecase_calls_total
 * - usecase_duration_ms
 */
@Slf4j
@Aspect
@Component
@RequiredArgsConstructor
@Order(100) // después de filtros web, antes de aspectos de auditoría si los hubiera
public class UseCaseLoggingMetricsAspect {

    private final MeterRegistry meterRegistry;

    /**
     * Pointcut para todos los servicios de la capa de aplicación (auth).
     * Puedes ampliarlo a otros módulos de aplicación si más adelante
     * tienes otros contextos (billing, orders, etc).
     */
    @Pointcut("execution(public * com.lanny.spring_security_template.application.auth.service..*(..))")
    public void authUseCaseOperation() {
        // Pointcut marker
    }

    @Around("authUseCaseOperation()")
    public Object logAndMeasure(ProceedingJoinPoint pjp) throws Throwable {

        long startNs = System.nanoTime();

        MethodSignature signature = (MethodSignature) pjp.getSignature();
        String className = signature.getDeclaringType().getSimpleName();
        String methodName = signature.getName();
        String useCase = className + "." + methodName;

        String correlationId = MDC.get("correlationId");
        String user = MDC.get("user");

        // IMPORTANTE: no loggeamos argumentos (pueden contener credenciales)
        log.debug("▶️ [USECASE_START] useCase={} correlationId={} user={}",
                useCase, correlationId, user);

        try {
            Object result = pjp.proceed();

            long durationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNs);

            // Métricas
            meterRegistry.counter("usecase_calls_total",
                    "usecase", useCase,
                    "status", "SUCCESS")
                    .increment();

            Timer.builder("usecase_duration_ms")
                    .tag("usecase", useCase)
                    .tag("status", "SUCCESS")
                    .register(meterRegistry)
                    .record(durationMs, TimeUnit.MILLISECONDS);

            log.info("✅ [USECASE_SUCCESS] useCase={} durationMs={} correlationId={} user={}",
                    useCase, durationMs, correlationId, user);

            return result;

        } catch (Throwable ex) {
            long durationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNs);

            meterRegistry.counter("usecase_calls_total",
                    "usecase", useCase,
                    "status", "ERROR")
                    .increment();

            Timer.builder("usecase_duration_ms")
                    .tag("usecase", useCase)
                    .tag("status", "ERROR")
                    .register(meterRegistry)
                    .record(durationMs, TimeUnit.MILLISECONDS);

            log.warn("❌ [USECASE_ERROR] useCase={} durationMs={} correlationId={} user={} error={}",
                    useCase, durationMs, correlationId, user, ex.getMessage());

            throw ex;
        }
    }
}
