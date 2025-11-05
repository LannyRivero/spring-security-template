package com.lanny.spring_security_template.application.auth.result;

import java.util.List;

public record MeResult(String userId, String username, List<String> roles, List<String> scopes) {
}
