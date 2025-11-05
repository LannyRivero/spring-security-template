package com.lanny.spring_security_template.infrastructure.web.auth.controller;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.port.in.AuthUseCase;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.result.MeResult;
import com.lanny.spring_security_template.infrastructure.web.auth.dto.*;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthUseCase authUseCase;

    @Value("${app.auth.register-enabled:false}")
    private boolean registerEnabled;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request) {
        JwtResult result = authUseCase.login(
                new LoginCommand(request.usernameOrEmail(), request.password())
        );
        return ResponseEntity.<AuthResponse>ok(
                new AuthResponse(result.accessToken(), result.refreshToken(), result.expiresAt())
        );
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        JwtResult result = authUseCase.refresh(new RefreshCommand(request.refreshToken()));
        return ResponseEntity.<AuthResponse>ok(
                new AuthResponse(result.accessToken(), result.refreshToken(), result.expiresAt())
        );
    }

    @GetMapping("/me")
    public ResponseEntity<MeResponse> me(@AuthenticationPrincipal UserDetails principal) {
        MeResult result = authUseCase.me(principal.getUsername());
        return ResponseEntity.<MeResponse>ok(
                new MeResponse(result.userId(), result.username(), result.roles(), result.scopes())
        );
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        if (!registerEnabled) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body("User registration is disabled in this environment");
        }

        // En un futuro: delegar a un RegisterUseCase o AuthUseCase.register()
        return ResponseEntity.status(HttpStatus.CREATED)
                .body("User '%s' registered successfully (dev mode)".formatted(request.username()));
    }
}

