package com.lanny.spring_security_template.infrastructure.security.policy;

import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.domain.model.Role;
import com.lanny.spring_security_template.domain.model.Scope;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;

/**
 * ============================================================
 * DefaultScopePolicy
 * ============================================================
 *
 * <p>
 * Default enterprise-grade implementation of {@link ScopePolicy}
 * responsible for resolving effective authorization scopes
 * from a set of domain {@link Role} objects.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 *   <li>Resolve effective scopes derived from roles</li>
 *   <li>Apply implicit authorization rules (ADMIN, SYSTEM)</li>
 *   <li>Answer fine-grained authorization checks</li>
 * </ul>
 *
 * <h2>Authorization model</h2>
 * <ul>
 *   <li><b>USER</b>: receives scopes explicitly defined in roles</li>
 *   <li><b>ADMIN</b>: receives declared scopes plus implicit admin scopes</li>
 *   <li><b>SYSTEM</b>: receives all known scopes defined by policy</li>
 * </ul>
 *
 * <p>
 * SYSTEM access represents <b>maximum known privileges</b>
 * defined by the policy, not an unbounded wildcard.
 * </p>
 *
 * <h2>Design characteristics</h2>
 * <ul>
 *   <li>Deterministic and side-effect free</li>
 *   <li>No exceptions thrown for authorization checks</li>
 *   <li>Thread-safe and stateless from caller perspective</li>
 *   <li>Optional in-memory caching for performance</li>
 * </ul>
 *
 * <h2>Extensibility</h2>
 * <p>
 * This implementation can be safely replaced by:
 * </p>
 * <ul>
 *   <li>Database-backed policies</li>
 *   <li>Tenant-aware authorization engines</li>
 *   <li>External IAM / PDP integrations</li>
 * </ul>
 *
 * <p>
 * Without impacting the application or domain layers.
 * </p>
 */

@Component
@Primary
@Profile({ "dev", "prod" })
public class DefaultScopePolicy implements ScopePolicy {

    /**
     * Implicit scopes granted by specific roles, on top of the scopes
     * explicitly held by the Role aggregate.
     *
     * Keys are normalized role names (e.g. "ROLE_ADMIN", "ROLE_SYSTEM").
     */
    private static final Map<String, Set<Scope>> IMPLICIT_ROLE_SCOPES = Map.of(
            "ROLE_ADMIN", Set.of(
                    Scope.of("profile:read"),
                    Scope.of("profile:write"),
                    Scope.of("user:manage"),
                    Scope.of("audit:read")
            ),
            "ROLE_SYSTEM", Set.of(
                    Scope.of("profile:read"),
                    Scope.of("profile:write"),
                    Scope.of("user:manage"),
                    Scope.of("audit:read"),
                    Scope.of("audit:write")
            )
    );

    /**
     * Optional small cache to avoid recomputing scopes for the same
     * role combinations over and over.
     *
     * Key format: sorted role names joined by comma, e.g. "ROLE_ADMIN,ROLE_USER".
     */
    private final Map<String, Set<Scope>> resolvedScopesCache = new ConcurrentHashMap<>();

    // ============================================================
    // 1) RESOLVER TODOS LOS SCOPES
    // ============================================================
    @Override
    public Set<Scope> resolveScopes(Set<Role> roles) {
        if (roles == null || roles.isEmpty()) {
            return Set.of();
        }

        // Si tiene ROLE_SYSTEM → acceso absoluto (por política de negocio)
        if (roles.stream().anyMatch(Role::isSystem)) {
            return resolveSystemScopes(roles);
        }

        // Si tiene ROLE_ADMIN → acceso muy amplio
        if (roles.stream().anyMatch(Role::isAdmin)) {
            return resolveAdminScopes(roles);
        }

        // Caso general → usamos cache
        String cacheKey = buildCacheKey(roles);
        return resolvedScopesCache.computeIfAbsent(cacheKey, key -> computeScopes(roles));
    }

    // ============================================================
    // 2) ¿TIENE UN SCOPE CONCRETO?
    // ============================================================
    @Override
    public boolean hasScope(String scopeName, Set<Role> roles) {
        if (scopeName == null || scopeName.isBlank()) {
            return false;
        }

        Set<Scope> scopes = resolveScopes(roles);
        return scopes.stream().anyMatch(scope -> scope.name().equalsIgnoreCase(scopeName));
    }

    // ============================================================
    // 3) ¿PUEDE HACER acción SOBRE recurso?
    // ============================================================
    @Override
    public boolean can(String action, String resource, Set<Role> roles) {
        if (action == null || resource == null) {
            return false;
        }

        Set<Scope> scopes = resolveScopes(roles);

        return scopes.stream().anyMatch(scope ->
                scope.action().equalsIgnoreCase(action)
                        && scope.resource().equalsIgnoreCase(resource));
    }

    // ============================================================
    // IMPLEMENTACIÓN INTERNA
    // ============================================================

    /**
     * Full “SYSTEM” policy:
     * - Uses all scopes from roles
     * - Plus all implicit scopes from SYSTEM and ADMINs
     * - Puede en el futuro ampliarse para "all known scopes" si se modelan en DB.
     */
    private Set<Scope> resolveSystemScopes(Set<Role> roles) {
        Set<Scope> result = new HashSet<>();

        // Scopes declarados directamente en los roles
        roles.forEach(role -> result.addAll(role.scopes()));

        // Scopes implícitos para SYSTEM & ADMIN
        roles.stream()
                .map(Role::name)
                .map(IMPLICIT_ROLE_SCOPES::get)
                .filter(Objects::nonNull)
                .forEach(result::addAll);

        // Aquí podrías añadir "todos los scopes del sistema"
        // si los obtienes de una tabla de configuración en DB.

        return Set.copyOf(result);
    }

    /**
     * “ADMIN” policy:
     * - Scopes declarados en roles
     * - Más scopes implícitos de ADMIN
     */
    private Set<Scope> resolveAdminScopes(Set<Role> roles) {
        Set<Scope> result = new HashSet<>();

        roles.forEach(role -> result.addAll(role.scopes()));

        roles.stream()
                .map(Role::name)
                .map(IMPLICIT_ROLE_SCOPES::get)
                .filter(Objects::nonNull)
                .forEach(result::addAll);

        return Set.copyOf(result);
    }

    /**
     * General case: no ADMIN / SYSTEM.
     */
    private Set<Scope> computeScopes(Set<Role> roles) {
        Set<Scope> result = new HashSet<>();

        // Scopes declarados por los roles
        roles.forEach(role -> result.addAll(role.scopes()));

        // Scopes implícitos específicos de cada rol normal (si aplicara)
        roles.stream()
                .map(Role::name)
                .map(IMPLICIT_ROLE_SCOPES::get)
                .filter(Objects::nonNull)
                .forEach(result::addAll);

        return Set.copyOf(result);
    }

    private String buildCacheKey(Set<Role> roles) {
        return roles.stream()
                .map(Role::name)
                .sorted()
                .collect(Collectors.joining(","));
    }
}

