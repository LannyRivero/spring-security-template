package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.result.JwtResult;

import java.time.Instant;
import java.util.List;

public record IssuedTokens(
        String username,
        String accessToken,
        String refreshToken,
        String refreshJti,
        Instant issuedAt,
        Instant accessExp,
        Instant refreshExp,
        List<String> roleNames,
        List<String> scopeNames) {

    public JwtResult toJwtResult() {
        return new JwtResult(accessToken, refreshToken, accessExp);
    }
}
