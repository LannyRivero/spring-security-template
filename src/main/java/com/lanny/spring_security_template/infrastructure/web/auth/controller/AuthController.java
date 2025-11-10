package com.lanny.spring_security_template.infrastructure.web.auth.controller;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.port.in.AuthUseCase;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.result.MeResult;
import com.lanny.spring_security_template.infrastructure.web.auth.dto.*;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

/**
 * 🔐 Authentication Controller — handles login, refresh, user info, and dev registration.
 */
@Tag(name = "Authentication", description = "Endpoints for JWT authentication and user info")
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthUseCase authUseCase;

    @Value("${app.auth.register-enabled:false}")
    private boolean registerEnabled;

    // -------------------------------------------------------------------------
    // 🔸 LOGIN
    // -------------------------------------------------------------------------
    @Operation(
            summary = "Authenticate user and issue JWT tokens",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Successful authentication",
                            content = @Content(schema = @Schema(implementation = AuthResponse.class))),
                    @ApiResponse(responseCode = "401", description = "Invalid credentials")
            }
    )
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request) {
        JwtResult result = authUseCase.login(new LoginCommand(request.usernameOrEmail(), request.password()));
        return ResponseEntity.ok(
                new AuthResponse(result.accessToken(), result.refreshToken(), result.expiresAt())
        );
    }

    // -------------------------------------------------------------------------
    // 🔸 REFRESH TOKEN
    // -------------------------------------------------------------------------
    @Operation(
            summary = "Refresh access token using a valid refresh token",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Access token refreshed",
                            content = @Content(schema = @Schema(implementation = AuthResponse.class))),
                    @ApiResponse(responseCode = "401", description = "Invalid refresh token")
            }
    )
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        JwtResult result = authUseCase.refresh(new RefreshCommand(request.refreshToken()));
        return ResponseEntity.ok(
                new AuthResponse(result.accessToken(), result.refreshToken(), result.expiresAt())
        );
    }

    // -------------------------------------------------------------------------
    // 🔸 CURRENT USER INFO
    // -------------------------------------------------------------------------
    @Operation(
            summary = "Get current authenticated user info",
            security = @SecurityRequirement(name = "bearerAuth"),
            responses = {
                    @ApiResponse(responseCode = "200", description = "User info returned",
                            content = @Content(schema = @Schema(implementation = MeResponse.class))),
                    @ApiResponse(responseCode = "401", description = "Unauthorized")
            }
    )
    @GetMapping("/me")
    public ResponseEntity<MeResponse> me(@AuthenticationPrincipal(expression = "username") String username) {
        MeResult result = authUseCase.me(username);
        return ResponseEntity.ok(
                new MeResponse(result.userId(), result.username(), result.roles(), result.scopes())
        );
    }

    // -------------------------------------------------------------------------
    // 🔸 REGISTER (DEV ONLY)
    // -------------------------------------------------------------------------
    @Operation(
            summary = "Register a new user (only enabled in dev mode)",
            responses = {
                    @ApiResponse(responseCode = "201", description = "User registered successfully"),
                    @ApiResponse(responseCode = "403", description = "Registration disabled")
            }
    )
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        if (!registerEnabled) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body("User registration is disabled in this environment");
        }

        var response = new MessageResponse(
                "User '%s' registered successfully (dev mode)".formatted(request.username())
        );

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // -------------------------------------------------------------------------
    // 🔸 LOCAL DTO
    // -------------------------------------------------------------------------
    private record MessageResponse(String message) {}
}


