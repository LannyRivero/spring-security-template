package com.lanny.spring_security_template.application.auth.port.out;

import java.util.Set;

import com.lanny.spring_security_template.domain.valueobject.Role;

public interface RoleProvider {
  Set<Role> resolveRoles(String username);
}
