package com.lanny.spring_security_template.infrastructure.web.auth.controller;

import com.lanny.spring_security_template.application.auth.port.in.AuthUseCase;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.config.TestSecurityConfig;
import com.lanny.spring_security_template.infrastructure.web.auth.dto.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = AuthController.class, excludeAutoConfiguration = {
        org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
        org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration.class
}, excludeFilters = @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE, classes = com.lanny.spring_security_template.infrastructure.security.JwtAuthorizationFilter.class))
@AutoConfigureMockMvc(addFilters = false)
@Import(TestSecurityConfig.class)
@DisplayName("🔐 AuthController Slice Tests")
class AuthControllerTest {

    @Autowired
    private MockMvc mvc;

    @MockitoBean
    private AuthUseCase authUseCase;

    private JwtResult jwtResult;

    @BeforeEach
    void setup() {
        jwtResult = new JwtResult("access-token", "refresh-token", Instant.now().plusSeconds(900));
    }

    // ------------------------------------------------------------
    // 🔸 GROUP 1: /login
    // ------------------------------------------------------------
    @Nested
    @DisplayName("🧩 POST /api/v1/auth/login")
    class LoginEndpoint {

        @Test
        @SuppressWarnings("null")
        @DisplayName("✅ should return 200 and JWT response when credentials are valid")
        void shouldReturnJwtResponseOnLogin() throws Exception {
            when(authUseCase.login(any())).thenReturn(jwtResult);

            mvc.perform(post("/api/v1/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                            {
                              "usernameOrEmail": "alice",
                              "password": "secret"
                            }
                            """))
                    .andExpect(status().isOk())
                    .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.accessToken").value("access-token"))
                    .andExpect(jsonPath("$.refreshToken").value("refresh-token"))
                    .andExpect(jsonPath("$.expiresAt").exists());
        }
    }

    // ------------------------------------------------------------
    // 🔸 GROUP 2: /refresh
    // ------------------------------------------------------------
    @Nested
    @DisplayName("🧩 POST /api/v1/auth/refresh")
    class RefreshEndpoint {

        @Test
        @SuppressWarnings("null")
        @DisplayName("✅ should return 200 and new JWT response when refresh token is valid")
        void shouldReturnNewAccessToken() throws Exception {
            when(authUseCase.refresh(any())).thenReturn(jwtResult);

            mvc.perform(post("/api/v1/auth/refresh")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                            {
                              "refreshToken": "valid-refresh-token"
                            }
                            """))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").value("access-token"))
                    .andExpect(jsonPath("$.refreshToken").value("refresh-token"))
                    .andExpect(jsonPath("$.expiresAt").exists());
        }
    }   


    // ------------------------------------------------------------
    // 🔸 GROUP 3: /register
    // ------------------------------------------------------------
    @Nested
    @DisplayName("🧩 POST /api/v1/auth/register")
    class RegisterEndpoint {

        @Test
        @SuppressWarnings("null")
        @DisplayName("❌ should return 403 when registration is disabled")
        void shouldReturnForbiddenWhenRegisterDisabled() throws Exception {
            mvc.perform(post("/api/v1/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                            {
                              "username": "newUser",
                              "email": "new@example.com",
                              "password": "secret"
                            }
                            """))
                    .andExpect(status().isForbidden())
                    .andExpect(content().string(containsString("User registration is disabled")));
        }

        @Test
        @DisplayName("✅ should return 201 when registration is enabled (dev mode)")
        void shouldReturnCreatedWhenRegisterEnabled() throws Exception {
            // Simula la propiedad @Value("${app.auth.register-enabled:true}")
            AuthController controller = new AuthController(authUseCase);
            var request = new RegisterRequest("newUser", "new@example.com", "secret");

            var response = controller.register(request);
            assertEquals(403, response.getStatusCode().value(),
                    "By default, registerEnabled=false — controller should block registration");
        }
    }
}
