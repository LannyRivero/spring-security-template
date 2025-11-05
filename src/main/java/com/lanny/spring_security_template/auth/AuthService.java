package com.lanny.spring_security_template.auth;

import com.lanny.spring_security_template.auth.dto.JwtResponse;
import com.lanny.spring_security_template.auth.dto.LoginRequest;
import com.lanny.spring_security_template.infrastructure.jwt.JwtClaimsExtractor;
import com.lanny.spring_security_template.infrastructure.jwt.JwtUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

@Service
public class AuthService {

    private final AuthenticationManager authManager;
    private final JwtUtils jwtUtils;
    private final JwtClaimsExtractor extractor;

    public AuthService(AuthenticationManager authManager, JwtUtils jwtUtils, JwtClaimsExtractor extractor) {
        this.authManager = authManager;
        this.jwtUtils = jwtUtils;
        this.extractor = extractor;
    }

    public JwtResponse login(LoginRequest request) {
        Authentication authentication = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(), request.password()));

        UserDetails user = (UserDetails) authentication.getPrincipal();
        List<String> roles = extractRoles(user);
        List<String> scopes = extractScopes(user);

        String access = jwtUtils.generateAccessToken(user.getUsername(), roles, scopes);
        String refresh = jwtUtils.generateRefreshToken(user.getUsername());

        JWTClaimsSet claims = jwtUtils.validateAndParse(access);
        Instant expiresAt = claims.getExpirationTime().toInstant();

        return new JwtResponse(access, refresh, expiresAt);
    }

    private List<String> extractRoles(UserDetails user) {
        return user.getAuthorities().stream()
                .filter(a -> a.getAuthority().startsWith("ROLE_"))
                .map(a -> a.getAuthority().replace("ROLE_", ""))
                .toList();
    }

    private List<String> extractScopes(UserDetails user) {
        return user.getAuthorities().stream()
                .filter(a -> a.getAuthority().startsWith("SCOPE_"))
                .map(a -> a.getAuthority().replace("SCOPE_", ""))
                .toList();
    }
}
