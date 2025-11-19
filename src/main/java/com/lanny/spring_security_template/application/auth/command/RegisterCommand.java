package com.lanny.spring_security_template.application.auth.command;

import java.util.List;

public record RegisterCommand(
        String username,
        String email,
        String rawPassword,
        List<String> roles,
        List<String> scopes) {
}
