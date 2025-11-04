package com.lanny.spring_security_template.web.controller;

import org.springframework.web.bind.annotation.RestController;

import com.lanny.spring_security_template.application.auth.port.in.AuthUseCase;
import com.lanny.spring_security_template.web.dto.AuthRequest;
import com.lanny.spring_security_template.web.dto.AuthResponse;
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

    @PostMapping("/refresh")
    public AuthResponse refresh(@RequestParam String refreshToken) {
        return authUseCase.refresh(refreshToken);
    }

    @GetMapping("/me")
    public AuthResponse me(@RequestParam String username) {
        return authUseCase.me(username);
    }
}
