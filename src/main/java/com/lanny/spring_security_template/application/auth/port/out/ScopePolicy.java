package com.lanny.spring_security_template.application.auth.port.out;

import java.util.Set;

import com.lanny.spring_security_template.domain.valueobject.Role;
import com.lanny.spring_security_template.domain.valueobject.Scope;

public interface ScopePolicy {

    /** 
     * Returns the full resolved set of scopes for the given roles.
     */
    Set<Scope> resolveScopes(Set<Role> roles);
}
