package com.lanny.spring_security_template.auth.dto;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonProperty;

public record MeResponse(
        @JsonProperty(required = true) String username,
        @JsonProperty(required = true) List<String> roles,
        @JsonProperty(required = true) List<String> scopes) {

    public MeResponse {
        roles = Objects.requireNonNullElse(roles, Collections.emptyList());
        scopes = Objects.requireNonNullElse(scopes, Collections.emptyList());
    }
}