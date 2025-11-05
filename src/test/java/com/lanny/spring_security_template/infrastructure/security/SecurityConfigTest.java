package com.lanny.spring_security_template.infrastructure.security;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.lanny.spring_security_template.infrastructure.jwt.nimbus.JwtUtils;

/**
 * 🚧 SecurityConfigTest
 * 
 * ⚠️ Este test es una verificación MOCK, no de integración real.
 * 
 * Usa @WebMvcTest y por tanto no levanta:
 *   - Filtros JWT reales
 *   - Configuración completa de Spring Security
 *   - Beans de Actuator ni rutas /api/v1/**
 *
 * Los tests de seguridad real están en {@link SecurityConfigIntegrationTest}.
 */
@Disabled("❌ Reemplazado por SecurityConfigIntegrationTest que valida seguridad real")
@WebMvcTest(controllers = SecureTestController.class)
class SecurityConfigTest {

    @Autowired MockMvc mvc;

    @MockitoBean JwtUtils jwtUtils;
    @MockitoBean JwtAuthorizationFilter jwtAuthz;
    @MockitoBean CustomAuthEntryPoint entryPoint;
    @MockitoBean CustomAccessDeniedHandler deniedHandler;

    @Test
    void shouldRejectUnauthorizedRequest() throws Exception {
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .get("/api/v1/secure/ping"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isUnauthorized());
    }

    @Test
    void shouldAcceptAuthorizedRequest() throws Exception {
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .get("/api/v1/secure/ping")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer fake.jwt.token")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk());
    }
}
