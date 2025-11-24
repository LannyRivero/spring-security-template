package com.lanny.spring_security_template.domain.policy;

import java.util.Set;

import com.lanny.spring_security_template.domain.model.Role;
import com.lanny.spring_security_template.domain.model.Scope;

public interface ScopePolicy {

    /** 
     * Returns the full resolved set of scopes for the given roles.
     */
    Set<Scope> resolveScopes(Set<Role> roles);
}
