package com.lanny.spring_security_template.infrastructure.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.lanny.spring_security_template.infrastructure.jwt.JwtUtils;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = SecureTestController.class)
@AutoConfigureMockMvc(addFilters = false)
class SecurityConfigTest {

    @Autowired MockMvc mvc;

    @MockitoBean JwtUtils jwtUtils;
    @MockitoBean JwtAuthorizationFilter jwtAuthz;
    @MockitoBean CustomAuthEntryPoint entryPoint;
    @MockitoBean CustomAccessDeniedHandler deniedHandler;

    @Test
    void shouldRejectUnauthorizedRequest() throws Exception {
        mvc.perform(get("/api/v1/secure/ping"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldAcceptAuthorizedRequest() throws Exception {
        String token = "Bearer fake.jwt.token";
        // Since JwtAuthorizationFilter is mocked, no need to mock JwtUtils
        // The filter won't execute its real logic

        mvc.perform(get("/actuator/health")
                .header(HttpHeaders.AUTHORIZATION, token)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }
}

