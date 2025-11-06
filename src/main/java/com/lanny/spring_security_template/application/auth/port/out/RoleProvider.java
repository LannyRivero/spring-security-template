package com.lanny.spring_security_template.application.auth.port.out;

import java.util.List;

public interface RoleProvider {
  List<String> resolveRoles(String username);
}
