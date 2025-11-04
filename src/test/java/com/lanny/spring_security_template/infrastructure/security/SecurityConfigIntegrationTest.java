package com.lanny.spring_security_template.infrastructure.security;

import com.lanny.spring_security_template.infrastructure.jwt.JwtUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class SecurityConfigIntegrationTest {

    @Autowired MockMvc mvc;
    @Autowired JwtUtils jwtUtils;

    @Test
    @DisplayName("🔒 Should return 401 when no token is provided")
    void shouldRejectRequestWithoutToken() throws Exception {
        mvc.perform(get("/api/v1/secure/ping"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("✅ Should return 200 when token has valid role and scope")
    void shouldAcceptRequestWithValidToken() throws Exception {
        String jwt = jwtUtils.generateAccessToken(
                "user@example.com",
                List.of("ROLE_USER"),
                List.of("profile:read")
        );

        mvc.perform(get("/api/v1/secure/ping")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("🚫 Should return 403 when token lacks correct scope")
    void shouldRejectRequestWithMissingScope() throws Exception {
        String jwt = jwtUtils.generateAccessToken(
                "user@example.com",
                List.of("ROLE_USER"),
                List.of("other:scope")
        );

        mvc.perform(get("/api/v1/secure/ping")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden());
    }
}

