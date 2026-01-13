package com.lanny.spring_security_template.infrastructure.security.provider;

import java.util.Set;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.domain.model.Role;
import com.lanny.spring_security_template.domain.model.Scope;

/**
 * ============================================================
 * InMemoryRoleProvider
 * ============================================================
 *
 * <p>
 * In-memory implementation of {@link RoleProvider} intended
 * <b>exclusively for development and demo environments</b>.
 * </p>
 *
 * <h2>Purpose</h2>
 * <p>
 * This provider exists to simplify local development and demos by
 * supplying a minimal, deterministic set of roles and scopes
 * without requiring external infrastructure.
 * </p>
 *
 * <p>
 * It allows developers to:
 * </p>
 * <ul>
 * <li>Develop and test authorization logic early</li>
 * <li>Run the application without a database or IAM system</li>
 * <li>Demonstrate role-based access control flows</li>
 * </ul>
 *
 * <h2>Behavior</h2>
 * <ul>
 * <li>Usernames equal to {@code "admin"} (case-insensitive) are
 * granted the {@code ADMIN} role with extended scopes</li>
 * <li>All other users are granted a basic {@code USER} role</li>
 * </ul>
 *
 * <h2>Important limitations</h2>
 * <ul>
 * <li>Roles and scopes are <b>hardcoded</b></li>
 * <li>No persistence or dynamic updates</li>
 * <li>No audit trail or role governance</li>
 * <li>No support for per-user customization</li>
 * </ul>
 *
 * <h2>Security warning</h2>
 * <p>
 * This implementation is <b>NOT suitable for production</b>.
 * </p>
 *
 * <p>
 * In production environments, roles must be resolved from a
 * controlled and auditable source such as:
 * </p>
 * <ul>
 * <li>Relational or NoSQL databases</li>
 * <li>Directory services (LDAP / IAM)</li>
 * <li>External authorization or identity providers</li>
 * </ul>
 *
 * <h2>Profiles</h2>
 * <p>
 * This bean is only active under the {@code dev} and {@code demo}
 * Spring profiles.
 * </p>
 *
 * <p>
 * Any attempt to activate this provider in {@code prod} should be
 * considered a configuration error and is expected to be prevented
 * by startup guards.
 * </p>
 */
@Component
@Profile({ "dev", "demo" })
public class InMemoryRoleProvider implements RoleProvider {

        @Override
        public Set<Role> resolveRoles(String username) {

                if ("admin".equalsIgnoreCase(username)) {
                        return Set.of(
                                        new Role(
                                                        "ADMIN",
                                                        Set.of(
                                                                        Scope.of("profile:read"),
                                                                        Scope.of("profile:write"),
                                                                        Scope.of("user:read"))));
                }

                return Set.of(
                                new Role(
                                                "USER",
                                                Set.of(
                                                                Scope.of("profile:read"))));
        }
}
