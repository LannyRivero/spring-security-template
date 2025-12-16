package com.lanny.spring_security_template.application.auth.audit;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks an application use case as auditable.
 *
 * This annotation explicitly declares that the annotated
 * operation produces a security-relevant audit event.
 *
 * Banking rationale:
 * - Audit events must be explicit and declarative
 * - No inference based on method names
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Auditable {

    AuditEvent event();

}

