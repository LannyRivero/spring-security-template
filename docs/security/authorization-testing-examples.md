# 🧪 Authorization Testing Examples

Complete test suite examples for scope-based authorization.

---

## Table of Contents

1. [Controller Tests (MockMvc)](#controller-tests-mockmvc)
2. [Service Layer Tests](#service-layer-tests)
3. [Integration Tests](#integration-tests)
4. [Test Utilities](#test-utilities)
5. [Edge Cases & Security Tests](#edge-cases--security-tests)

---

## Controller Tests (MockMvc)

### Basic Authorization Test

```java
package com.lanny.spring_security_template.application.rest;

import com.lanny.spring_security_template.infrastructure.security.TokenProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Duration;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("User Controller Authorization Tests")
class UserControllerAuthorizationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TokenProvider tokenProvider;

    @Nested
    @DisplayName("GET /api/users - List all users")
    class ListUsersTests {

        @Test
        @DisplayName("Should allow access with user:read scope")
        void shouldAllowWithUserReadScope() throws Exception {
            String token = generateToken("john.doe", List.of("user:read"));

            mockMvc.perform(get("/api/users")
                    .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
        }

        @Test
        @DisplayName("Should allow access with user:manage scope")
        void shouldAllowWithUserManageScope() throws Exception {
            String token = generateToken("admin", List.of("user:manage"));

            mockMvc.perform(get("/api/users")
                    .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
        }

        @Test
        @DisplayName("Should deny access without user:read scope")
        void shouldDenyWithoutUserReadScope() throws Exception {
            String token = generateToken("john.doe", List.of("profile:read"));

            mockMvc.perform(get("/api/users")
                    .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("Forbidden"))
                .andExpect(jsonPath("$.message").exists());
        }

        @Test
        @DisplayName("Should deny access without authentication")
        void shouldDenyWithoutAuthentication() throws Exception {
            mockMvc.perform(get("/api/users"))
                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Should deny access with invalid token")
        void shouldDenyWithInvalidToken() throws Exception {
            mockMvc.perform(get("/api/users")
                    .header("Authorization", "Bearer invalid-token-xyz"))
                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Should deny access with expired token")
        void shouldDenyWithExpiredToken() throws Exception {
            String token = generateToken("john.doe", List.of("user:read"), Duration.ofMillis(1));
            
            // Wait for token expiration
            Thread.sleep(100);

            mockMvc.perform(get("/api/users")
                    .header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("POST /api/users - Create user")
    class CreateUserTests {

        @Test
        @DisplayName("Should allow user creation with user:write scope")
        void shouldAllowWithUserWriteScope() throws Exception {
            String token = generateToken("admin", List.of("user:write"));
            String requestBody = """
                {
                    "username": "newuser",
                    "email": "newuser@example.com",
                    "password": "SecurePass123!"
                }
                """;

            mockMvc.perform(post("/api/users")
                    .header("Authorization", "Bearer " + token)
                    .contentType("application/json")
                    .content(requestBody))
                .andExpect(status().isCreated());
        }

        @Test
        @DisplayName("Should deny user creation with only user:read scope")
        void shouldDenyWithOnlyUserReadScope() throws Exception {
            String token = generateToken("viewer", List.of("user:read"));
            String requestBody = """
                {
                    "username": "newuser",
                    "email": "newuser@example.com",
                    "password": "SecurePass123!"
                }
                """;

            mockMvc.perform(post("/api/users")
                    .header("Authorization", "Bearer " + token)
                    .contentType("application/json")
                    .content(requestBody))
                .andExpect(status().isForbidden());
        }
    }

    @Nested
    @DisplayName("DELETE /api/users/{id} - Delete user")
    class DeleteUserTests {

        @Test
        @DisplayName("Should allow deletion with user:delete scope")
        void shouldAllowWithUserDeleteScope() throws Exception {
            String token = generateToken("admin", List.of("user:delete"));

            mockMvc.perform(delete("/api/users/user-123")
                    .header("Authorization", "Bearer " + token))
                .andExpect(status().isNoContent());
        }

        @Test
        @DisplayName("Should allow deletion with user:manage scope")
        void shouldAllowWithUserManageScope() throws Exception {
            String token = generateToken("admin", List.of("user:manage"));

            mockMvc.perform(delete("/api/users/user-123")
                    .header("Authorization", "Bearer " + token))
                .andExpect(status().isNoContent());
        }

        @Test
        @DisplayName("Should deny deletion with only user:read scope")
        void shouldDenyWithOnlyReadScope() throws Exception {
            String token = generateToken("viewer", List.of("user:read"));

            mockMvc.perform(delete("/api/users/user-123")
                    .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
        }
    }

    // Helper methods
    private String generateToken(String username, List<String> scopes) {
        return generateToken(username, scopes, Duration.ofMinutes(15));
    }

    private String generateToken(String username, List<String> scopes, Duration validity) {
        return tokenProvider.generateAccessToken(
            username,
            List.of("ROLE_USER"),
            scopes,
            validity
        );
    }
}
```

---

## Service Layer Tests

### Using @WithMockUser

```java
package com.lanny.spring_security_template.application.service;

import com.lanny.spring_security_template.domain.model.User;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.test.context.support.WithMockUser;

import java.util.List;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest
@DisplayName("User Service Authorization Tests")
class UserServiceAuthorizationTest {

    @Autowired
    private UserService userService;

    @Nested
    @DisplayName("findAll() method")
    class FindAllTests {

        @Test
        @DisplayName("Should allow findAll with user:read scope")
        @WithMockUser(username = "viewer", authorities = {"SCOPE_user:read"})
        void shouldAllowFindAllWithUserReadScope() {
            List<User> users = userService.findAll();
            
            assertThat(users).isNotNull();
        }

        @Test
        @DisplayName("Should allow findAll with user:manage scope")
        @WithMockUser(username = "admin", authorities = {"SCOPE_user:manage"})
        void shouldAllowFindAllWithUserManageScope() {
            List<User> users = userService.findAll();
            
            assertThat(users).isNotNull();
        }

        @Test
        @DisplayName("Should deny findAll without user:read scope")
        @WithMockUser(username = "user", authorities = {"SCOPE_profile:read"})
        void shouldDenyFindAllWithoutUserReadScope() {
            assertThatThrownBy(() -> userService.findAll())
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("Access Denied");
        }

        @Test
        @DisplayName("Should deny findAll without authentication")
        void shouldDenyFindAllWithoutAuthentication() {
            assertThatThrownBy(() -> userService.findAll())
                .isInstanceOf(AccessDeniedException.class);
        }
    }

    @Nested
    @DisplayName("create() method")
    class CreateUserTests {

        @Test
        @DisplayName("Should allow create with user:write scope")
        @WithMockUser(username = "admin", authorities = {"SCOPE_user:write"})
        void shouldAllowCreateWithUserWriteScope() {
            CreateUserRequest request = new CreateUserRequest(
                "newuser",
                "newuser@example.com",
                "SecurePass123!"
            );

            User user = userService.create(request);
            
            assertThat(user).isNotNull();
            assertThat(user.getUsername()).isEqualTo("newuser");
        }

        @Test
        @DisplayName("Should deny create without user:write scope")
        @WithMockUser(username = "viewer", authorities = {"SCOPE_user:read"})
        void shouldDenyCreateWithoutUserWriteScope() {
            CreateUserRequest request = new CreateUserRequest(
                "newuser",
                "newuser@example.com",
                "SecurePass123!"
            );

            assertThatThrownBy(() -> userService.create(request))
                .isInstanceOf(AccessDeniedException.class);
        }
    }

    @Nested
    @DisplayName("delete() method")
    class DeleteUserTests {

        @Test
        @DisplayName("Should allow delete with user:delete scope")
        @WithMockUser(username = "admin", authorities = {"SCOPE_user:delete"})
        void shouldAllowDeleteWithUserDeleteScope() {
            assertThatCode(() -> userService.delete("user-123"))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should allow delete with user:manage scope")
        @WithMockUser(username = "admin", authorities = {"SCOPE_user:manage"})
        void shouldAllowDeleteWithUserManageScope() {
            assertThatCode(() -> userService.delete("user-123"))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should deny delete without user:delete scope")
        @WithMockUser(username = "user", authorities = {"SCOPE_user:read"})
        void shouldDenyDeleteWithoutUserDeleteScope() {
            assertThatThrownBy(() -> userService.delete("user-123"))
                .isInstanceOf(AccessDeniedException.class);
        }
    }
}
```

---

### Using Custom Authentication

```java
package com.lanny.spring_security_template.application.service;

import com.lanny.spring_security_template.testsupport.TestAuthenticationBuilder;
import com.lanny.spring_security_template.domain.model.Profile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest
class ProfileServiceAuthorizationTest {

    @Autowired
    private ProfileService profileService;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldAllowProfileReadWithCorrectScope() {
        Authentication auth = TestAuthenticationBuilder.aUser()
            .withUsername("john.doe")
            .withScopes("profile:read")
            .build();
        SecurityContextHolder.getContext().setAuthentication(auth);

        Profile profile = profileService.getMyProfile();

        assertThat(profile).isNotNull();
        assertThat(profile.getUsername()).isEqualTo("john.doe");
    }

    @Test
    void shouldDenyProfileReadWithoutScope() {
        Authentication auth = TestAuthenticationBuilder.aUser()
            .withUsername("john.doe")
            .withScopes("user:read")
            .build();
        SecurityContextHolder.getContext().setAuthentication(auth);

        assertThatThrownBy(() -> profileService.getMyProfile())
            .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void shouldAllowProfileUpdateForOwner() {
        Authentication auth = TestAuthenticationBuilder.aUser()
            .withUsername("john.doe")
            .withScopes("profile:write")
            .build();
        SecurityContextHolder.getContext().setAuthentication(auth);

        UpdateProfileRequest request = new UpdateProfileRequest("John", "Doe", "Bio");

        assertThatCode(() -> profileService.updateProfile("profile-john-doe", request))
            .doesNotThrowAnyException();
    }

    @Test
    void shouldDenyProfileUpdateForNonOwner() {
        Authentication auth = TestAuthenticationBuilder.aUser()
            .withUsername("jane.doe")
            .withScopes("profile:write")
            .build();
        SecurityContextHolder.getContext().setAuthentication(auth);

        UpdateProfileRequest request = new UpdateProfileRequest("John", "Doe", "Bio");

        assertThatThrownBy(() -> profileService.updateProfile("profile-john-doe", request))
            .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void shouldAllowProfileUpdateForAdminWithManageScope() {
        Authentication auth = TestAuthenticationBuilder.aUser()
            .withUsername("admin")
            .withScopes("user:manage")
            .build();
        SecurityContextHolder.getContext().setAuthentication(auth);

        UpdateProfileRequest request = new UpdateProfileRequest("John", "Doe", "Bio");

        assertThatCode(() -> profileService.updateProfile("profile-john-doe", request))
            .doesNotThrowAnyException();
    }
}
```

---

## Integration Tests

### Full Flow Test

```java
package com.lanny.spring_security_template.integration;

import com.lanny.spring_security_template.application.rest.dto.LoginRequest;
import com.lanny.spring_security_template.application.rest.dto.CreateUserRequest;
import com.lanny.spring_security_template.infrastructure.security.TokenProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("Authorization Integration Tests")
class AuthorizationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("Full flow: Register → Login → Access Protected Resource")
    void shouldCompleteFullAuthorizationFlow() throws Exception {
        // 1. Register new user
        CreateUserRequest registerRequest = new CreateUserRequest(
            "testuser",
            "testuser@example.com",
            "SecurePass123!"
        );

        mockMvc.perform(post("/api/auth/register")
                .contentType("application/json")
                .content(objectMapper.writeValueAsString(registerRequest)))
            .andExpect(status().isCreated());

        // 2. Login
        LoginRequest loginRequest = new LoginRequest("testuser", "SecurePass123!");

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                .contentType("application/json")
                .content(objectMapper.writeValueAsString(loginRequest)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accessToken").exists())
            .andReturn();

        String responseBody = loginResult.getResponse().getContentAsString();
        String accessToken = objectMapper.readTree(responseBody).get("accessToken").asText();

        // 3. Access protected resource (should have profile:read scope by default)
        mockMvc.perform(get("/api/profile")
                .header("Authorization", "Bearer " + accessToken))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value("testuser"));

        // 4. Try to access admin resource (should fail)
        mockMvc.perform(get("/api/users")
                .header("Authorization", "Bearer " + accessToken))
            .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Admin flow: Admin can access all resources")
    void adminShouldAccessAllResources() throws Exception {
        // Login as admin (seeded in database)
        LoginRequest loginRequest = new LoginRequest("admin", "admin123");

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                .contentType("application/json")
                .content(objectMapper.writeValueAsString(loginRequest)))
            .andExpect(status().isOk())
            .andReturn();

        String responseBody = loginResult.getResponse().getContentAsString();
        String accessToken = objectMapper.readTree(responseBody).get("accessToken").asText();

        // Should access user list
        mockMvc.perform(get("/api/users")
                .header("Authorization", "Bearer " + accessToken))
            .andExpect(status().isOk());

        // Should access profiles
        mockMvc.perform(get("/api/profile")
                .header("Authorization", "Bearer " + accessToken))
            .andExpect(status().isOk());

        // Should create new user
        CreateUserRequest newUser = new CreateUserRequest(
            "newadminuser",
            "newadminuser@example.com",
            "SecurePass123!"
        );

        mockMvc.perform(post("/api/users")
                .header("Authorization", "Bearer " + accessToken)
                .contentType("application/json")
                .content(objectMapper.writeValueAsString(newUser)))
            .andExpect(status().isCreated());

        // Should delete user
        mockMvc.perform(delete("/api/users/user-123")
                .header("Authorization", "Bearer " + accessToken))
            .andExpect(status().isNoContent());
    }
}
```

---

## Test Utilities

### TestAuthenticationBuilder

```java
package com.lanny.spring_security_template.testsupport;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Builder for creating test Authentication objects with scopes.
 * 
 * <p>Usage:
 * <pre>
 * Authentication auth = TestAuthenticationBuilder.aUser()
 *     .withUsername("john.doe")
 *     .withScopes("user:read", "profile:write")
 *     .build();
 * </pre>
 */
public class TestAuthenticationBuilder {

    private String username = "test-user";
    private List<String> roles = new ArrayList<>(List.of("ROLE_USER"));
    private List<String> scopes = new ArrayList<>();

    private TestAuthenticationBuilder() {
    }

    public static TestAuthenticationBuilder aUser() {
        return new TestAuthenticationBuilder();
    }

    public static TestAuthenticationBuilder anAdmin() {
        return new TestAuthenticationBuilder()
            .withRoles("ROLE_ADMIN")
            .withScopes("user:manage", "profile:read", "profile:write");
    }

    public TestAuthenticationBuilder withUsername(String username) {
        this.username = username;
        return this;
    }

    public TestAuthenticationBuilder withRoles(String... roles) {
        this.roles = Arrays.asList(roles);
        return this;
    }

    public TestAuthenticationBuilder withScopes(String... scopes) {
        this.scopes = Arrays.asList(scopes);
        return this;
    }

    public TestAuthenticationBuilder addScope(String scope) {
        this.scopes.add(scope);
        return this;
    }

    public Authentication build() {
        List<GrantedAuthority> authorities = new ArrayList<>();

        // Add roles
        authorities.addAll(roles.stream()
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList()));

        // Add scopes
        authorities.addAll(scopes.stream()
            .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
            .collect(Collectors.toList()));

        return new UsernamePasswordAuthenticationToken(
            username,
            null,
            authorities
        );
    }
}
```

### TokenTestHelper

```java
package com.lanny.spring_security_template.testutil;

import com.lanny.spring_security_template.infrastructure.security.TokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.List;

/**
 * Helper class for generating test JWT tokens.
 */
@Component
public class TokenTestHelper {

    @Autowired
    private TokenProvider tokenProvider;

    /**
     * Generate access token with default validity (15 minutes)
     */
    public String generateAccessToken(String username, List<String> scopes) {
        return generateAccessToken(username, List.of("ROLE_USER"), scopes, Duration.ofMinutes(15));
    }

    /**
     * Generate access token with custom validity
     */
    public String generateAccessToken(String username, List<String> scopes, Duration validity) {
        return generateAccessToken(username, List.of("ROLE_USER"), scopes, validity);
    }

    /**
     * Generate access token with roles and scopes
     */
    public String generateAccessToken(String username, List<String> roles, List<String> scopes, Duration validity) {
        return tokenProvider.generateAccessToken(username, roles, scopes, validity);
    }

    /**
     * Generate admin token with all scopes
     */
    public String generateAdminToken() {
        return generateAccessToken(
            "admin",
            List.of("ROLE_ADMIN"),
            List.of("user:manage", "profile:read", "profile:write", "audit:read", "system:config"),
            Duration.ofMinutes(15)
        );
    }

    /**
     * Generate user token with basic scopes
     */
    public String generateUserToken(String username) {
        return generateAccessToken(
            username,
            List.of("ROLE_USER"),
            List.of("profile:read", "profile:write"),
            Duration.ofMinutes(15)
        );
    }

    /**
     * Generate expired token for testing
     */
    public String generateExpiredToken(String username) {
        return generateAccessToken(
            username,
            List.of("ROLE_USER"),
            List.of("profile:read"),
            Duration.ofMillis(1)
        );
    }
}
```

---

## Edge Cases & Security Tests

### Boundary Tests

```java
package com.lanny.spring_security_template.security;

import com.lanny.spring_security_template.testutil.TokenTestHelper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Duration;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("Security Edge Cases Tests")
class SecurityEdgeCasesTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TokenTestHelper tokenHelper;

    @Test
    @DisplayName("Should reject token with empty scopes list")
    void shouldRejectEmptyScopes() throws Exception {
        String token = tokenHelper.generateAccessToken("user", List.of());

        mockMvc.perform(get("/api/users")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Should reject malformed bearer token")
    void shouldRejectMalformedToken() throws Exception {
        mockMvc.perform(get("/api/users")
                .header("Authorization", "Bearer "))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should reject bearer token without 'Bearer' prefix")
    void shouldRejectTokenWithoutBearerPrefix() throws Exception {
        String token = tokenHelper.generateAccessToken("user", List.of("user:read"));

        mockMvc.perform(get("/api/users")
                .header("Authorization", token))  // Missing "Bearer "
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should reject token with typo in scope name")
    void shouldRejectTypoInScope() throws Exception {
        String token = tokenHelper.generateAccessToken("user", List.of("user:raed"));  // Typo: "raed"

        mockMvc.perform(get("/api/users")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Should reject token with case-sensitive scope mismatch")
    void shouldRejectCaseSensitiveMismatch() throws Exception {
        String token = tokenHelper.generateAccessToken("user", List.of("User:Read"));  // Wrong case

        mockMvc.perform(get("/api/users")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Should handle multiple authorization headers (use first)")
    void shouldHandleMultipleAuthHeaders() throws Exception {
        String validToken = tokenHelper.generateUserToken("user");
        String invalidToken = "invalid-token";

        mockMvc.perform(get("/api/profile")
                .header("Authorization", "Bearer " + validToken)
                .header("Authorization", "Bearer " + invalidToken))
            .andExpect(status().isOk());  // Should use first header
    }

    @Test
    @DisplayName("Should reject token after blacklisting")
    void shouldRejectBlacklistedToken() throws Exception {
        String token = tokenHelper.generateUserToken("user");

        // Logout (blacklist token)
        mockMvc.perform(post("/api/auth/logout")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isNoContent());

        // Try to use blacklisted token
        mockMvc.perform(get("/api/profile")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should enforce scope separation (profile:read != user:read)")
    void shouldEnforceScopeSeparation() throws Exception {
        String token = tokenHelper.generateAccessToken("user", List.of("profile:read"));

        // Can access profile
        mockMvc.perform(get("/api/profile")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isOk());

        // Cannot access users (needs user:read)
        mockMvc.perform(get("/api/users")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isForbidden());
    }
}
```

---

### Concurrent Access Tests

```java
package com.lanny.spring_security_template.security;

import com.lanny.spring_security_template.testutil.TokenTestHelper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("Concurrent Authorization Tests")
class ConcurrentAuthorizationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TokenTestHelper tokenHelper;

    @Test
    @DisplayName("Should handle concurrent requests with same token")
    void shouldHandleConcurrentRequests() throws Exception {
        String token = tokenHelper.generateAccessToken("user", List.of("profile:read"));
        
        ExecutorService executor = Executors.newFixedThreadPool(10);

        List<CompletableFuture<Void>> futures = List.of(
            CompletableFuture.runAsync(() -> makeRequest(token), executor),
            CompletableFuture.runAsync(() -> makeRequest(token), executor),
            CompletableFuture.runAsync(() -> makeRequest(token), executor),
            CompletableFuture.runAsync(() -> makeRequest(token), executor),
            CompletableFuture.runAsync(() -> makeRequest(token), executor)
        );

        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

        executor.shutdown();
    }

    private void makeRequest(String token) {
        try {
            mockMvc.perform(get("/api/profile")
                    .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
```

---

## Test Coverage Checklist

Use this checklist to ensure complete authorization testing:

- [ ] **Happy Path**
  - [ ] Access with correct scope
  - [ ] Access with admin/elevated scope

- [ ] **Negative Cases**
  - [ ] Access without scope
  - [ ] Access with wrong scope
  - [ ] Access without authentication

- [ ] **Token Validation**
  - [ ] Expired token
  - [ ] Invalid token
  - [ ] Malformed token
  - [ ] Blacklisted token

- [ ] **Scope Boundaries**
  - [ ] Exact scope match
  - [ ] Scope typo rejection
  - [ ] Case sensitivity
  - [ ] Scope separation (profile:read ≠ user:read)

- [ ] **Edge Cases**
  - [ ] Empty scopes
  - [ ] Multiple authorization headers
  - [ ] Concurrent requests

- [ ] **Integration Tests**
  - [ ] Full registration → login → access flow
  - [ ] Admin vs. user role differences
  - [ ] Cross-resource access patterns

---

## References

- [Scope Implementation Guide](scope-implementation-guide.md)
- [RBAC+ABAC Matrix](rbac-abac-matrix.md)
- [Spring Security Testing](https://docs.spring.io/spring-security/reference/servlet/test/index.html)

---

**Last Updated**: 2025-12-26  
**Maintainer**: Security Team
