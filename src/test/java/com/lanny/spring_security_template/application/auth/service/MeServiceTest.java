package com.lanny.spring_security_template.application.auth.service;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.application.auth.result.MeResult;
import com.lanny.spring_security_template.domain.model.Role;
import com.lanny.spring_security_template.domain.model.Scope;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import com.lanny.spring_security_template.domain.valueobject.EmailAddress;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;
import com.lanny.spring_security_template.domain.valueobject.Username;

/**
 *  Unit tests for {@link MeService}.
 *
 * <p>
 * This test verifies that {@link MeService} correctly orchestrates user
 * retrieval,
 * role resolution, and scope expansion based on the current authenticated
 * username.
 * </p>
 *
 * <h2>Covered Scenarios</h2>
 * <ul>
 * <li>✔ User exists → returns {@link MeResult} with roles and scopes.</li>
 * <li> User not found → throws {@link UsernameNotFoundException}.</li>
 * <li>✔ Empty roles handled gracefully.</li>
 * <li>✔ Empty scopes when roles exist.</li>
 * </ul>
 *
 * <h2>Test Design</h2>
 * <ul>
 * <li>All collaborators are mocked to isolate the service logic.</li>
 * <li>No persistence or framework dependency (pure unit test).</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class MeServiceTest {

    @Mock
    private UserAccountGateway userAccountGateway;
    @Mock
    private RoleProvider roleProvider;
    @Mock
    private ScopePolicy scopePolicy;

    @InjectMocks
    private MeService meService;

    private User realUser;

    @BeforeEach
    void setUp() {
        realUser = User.createNew(
                Username.of("lanny"),
                EmailAddress.of("lanny@example.com"),
                PasswordHash.of("$2a$10$abcdefghijklmnopqrstuv12345678901234567890"),
                List.of("ROLE_USER"),
                List.of("profile:read"));
    }

    @Test
    @DisplayName(" Should return MeResult with roles and scopes when user exists")
    void testShouldReturnMeResultWhenUserExists() {
        // Arrange
        String username = "lanny";
        Scope read = Scope.of("profile:read");
        Scope write = Scope.of("profile:write");

        Role admin = new Role("ADMIN", Set.of(read, write));
        Role userRole = new Role("USER", Set.of(read));

        when(userAccountGateway.findByUsernameOrEmail(username)).thenReturn(Optional.of(realUser));
        when(roleProvider.resolveRoles(username)).thenReturn(Set.of(admin, userRole));
        when(scopePolicy.resolveScopes(Set.of(admin, userRole))).thenReturn(Set.of(read, write));

        // Act
        MeResult result = meService.me(username);

        // Assert
        assertThat(result.username()).isEqualTo(username);
        assertThat(result.roles()).containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_USER");
        assertThat(result.scopes()).containsExactlyInAnyOrder("profile:read", "profile:write");

        verify(userAccountGateway).findByUsernameOrEmail(username);
        verify(roleProvider).resolveRoles(username);
        verify(scopePolicy).resolveScopes(Set.of(admin, userRole));
    }

    @Test
    @DisplayName(" Should throw UsernameNotFoundException when user not found")
    void testShouldThrowWhenUserNotFound() {
        // Arrange
        when(userAccountGateway.findByUsernameOrEmail("ghost")).thenReturn(Optional.empty());

        // Act & Assert
        assertThatThrownBy(() -> meService.me("ghost"))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("ghost");

        verify(userAccountGateway).findByUsernameOrEmail("ghost");
        verifyNoInteractions(roleProvider, scopePolicy);
    }

    @Test
    @DisplayName(" Should handle empty roles gracefully")
    void testShouldHandleEmptyRolesGracefully() {
        // Arrange
        String username = "lanny";
        when(userAccountGateway.findByUsernameOrEmail(username)).thenReturn(Optional.of(realUser));
        when(roleProvider.resolveRoles(username)).thenReturn(Set.of());
        when(scopePolicy.resolveScopes(Set.of())).thenReturn(Set.of());

        // Act
        MeResult result = meService.me(username);

        // Assert
        assertThat(result.roles()).isEmpty();
        assertThat(result.scopes()).isEmpty();
        assertThat(result.username()).isEqualTo(username);
    }

    @Test
    @DisplayName(" Should handle empty scopes even when roles exist")
    void testShouldHandleEmptyScopesEvenWithRoles() {
        // Arrange
        String username = "lanny";
        Scope read = Scope.of("profile:read");
        Role admin = new Role("ADMIN", Set.of(read));

        when(userAccountGateway.findByUsernameOrEmail(username)).thenReturn(Optional.of(realUser));
        when(roleProvider.resolveRoles(username)).thenReturn(Set.of(admin));
        when(scopePolicy.resolveScopes(Set.of(admin))).thenReturn(Set.of());

        // Act
        MeResult result = meService.me(username);

        // Assert
        assertThat(result.roles()).containsExactly("ROLE_ADMIN");
        assertThat(result.scopes()).isEmpty();
    }
}
