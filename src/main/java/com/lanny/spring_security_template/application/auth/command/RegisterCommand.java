package com.lanny.spring_security_template.application.auth.command;

public record RegisterCommand(String username, String email, String password) {
}
