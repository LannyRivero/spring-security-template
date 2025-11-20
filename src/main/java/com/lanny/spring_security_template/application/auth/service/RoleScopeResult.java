package com.lanny.spring_security_template.application.auth.service;

import java.util.List;

public record RoleScopeResult(
        List<String> roleNames,
        List<String> scopeNames
) { }
