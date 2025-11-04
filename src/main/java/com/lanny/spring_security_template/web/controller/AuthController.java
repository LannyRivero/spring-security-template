package com.lanny.spring_security_template.web.controller;

import org.springframework.web.bind.annotation.RestController;

import com.lanny.spring_security_template.application.auth.port.in.AuthUseCase;
import com.lanny.spring_security_template.web.dto.AuthRequest;
import com.lanny.spring_security_template.web.dto.AuthResponse;
import com.lanny.spring_security_template.web.dto.RegisterRequest;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthUseCase authUseCase;

    public AuthController(AuthUseCase authUseCase) {
        this.authUseCase = authUseCase;
    }

    @PostMapping("/login")
    public AuthResponse login(@RequestBody AuthRequest request) {
        return authUseCase.login(request);
    }

    @PostMapping("/register")
    public AuthResponse register(@RequestBody RegisterRequest request) {
        return authUseCase.register(request);
    }
}
