package com.lanny.spring_security_template.application.auth.port.out;

import java.util.Set;

import com.lanny.spring_security_template.domain.model.Role;

/**
 * Outbound port that provides the roles associated with a given user identity.
 *
 * <p>This port allows the application layer to retrieve domain-level {@link Role}
 * objects without depending on any specific infrastructure implementation
 * such as JPA, LDAP, external identity providers, or in-memory fixtures.</p>
 *
 * <p><strong>Identifier semantics:</strong>
 * The lookup is currently performed using the username, but future adapters
 * may support alternative identifiers (userId, email, external provider IDs)
 * without changing the application layer.</p>
 *
 * <p>Typical adapters:</p>
 * <ul>
 *   <li>JPA adapter using RoleEntity</li>
 *   <li>LDAP/Active Directory group mapping</li>
 *   <li>Keycloak/OPA/External IAM provider</li>
 *   <li>In-memory adapter for testing</li>
 * </ul>
 *
 * <p>The returned roles are immutable and represent domain-granted
 * authorities, ready to be integrated with scope policies and token
 * generation (JWT claims).</p>
 */
public interface RoleProvider {

    /**
     * Resolves all domain {@link Role} objects granted to the user identified
     * by the provided username.
     *
     * @param username the unique username of the target user
     * @return an immutable {@link Set} of {@link Role} instances
     */
    Set<Role> resolveRoles(String username);
}

