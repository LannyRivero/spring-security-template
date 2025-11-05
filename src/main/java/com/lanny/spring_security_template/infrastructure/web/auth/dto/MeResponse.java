package com.lanny.spring_security_template.infrastructure.web.auth.dto;

import java.util.List;

public record MeResponse(String userId, String username, List<String> roles, List<String> scopes) {
}
