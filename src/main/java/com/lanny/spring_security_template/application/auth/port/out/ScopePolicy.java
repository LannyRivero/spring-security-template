package com.lanny.spring_security_template.application.auth.port.out;

import java.util.List;

public interface ScopePolicy {
    List<String> defaultScopesFor(List<String> roles);

    boolean isAllowed(String scope); // extensible
}
