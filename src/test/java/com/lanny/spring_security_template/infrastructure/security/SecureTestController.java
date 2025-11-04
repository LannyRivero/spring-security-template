package com.lanny.spring_security_template.infrastructure.security;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

@RestController
public class SecureTestController {

    @PreAuthorize("hasRole('USER') and hasAuthority('SCOPE_profile:read')")
    @GetMapping("/api/v1/secure/ping")
    public Map<String, Object> ping() {
        return Map.of("status", "ok", "timestamp", Instant.now().toString());
    }
}
