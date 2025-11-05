package com.lanny.spring_security_template.auth;

import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

import com.lanny.spring_security_template.auth.dto.JwtResponse;
import com.lanny.spring_security_template.auth.dto.LoginRequest;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public JwtResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request);
    }

}
