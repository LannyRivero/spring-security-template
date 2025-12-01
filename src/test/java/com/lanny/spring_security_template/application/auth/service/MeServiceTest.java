package com.lanny.spring_security_template.application.auth.service;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.application.auth.result.MeResult;
import com.lanny.spring_security_template.domain.exception.UserNotFoundException;
import com.lanny.spring_security_template.domain.model.Role;
import com.lanny.spring_security_template.domain.model.Scope;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import com.lanny.spring_security_template.domain.valueobject.EmailAddress;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;
import com.lanny.spring_security_template.domain.valueobject.Username;
import com.lanny.spring_security_template.infrastructure.mapper.DomainModelMapper;

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

    private User buildUser() {
        return User.createNew(
                Username.of("lanny"),
                EmailAddress.of("lanny@example.com"),
                PasswordHash.of("$2a$10$abcdefghijklmnopqrstuv1234567890ABCDE"),
                DomainModelMapper.toRoles(List.of("ROLE_USER")),
                DomainModelMapper.toScopes(List.of("profile:read")));
    }

    @Test
    @DisplayName("me() → should return MeResult with resolved roles and scopes")
    void testShouldReturnMeResultWhenUserExists() {

        String username = "lanny";
        User user = buildUser();

        // Scopes
        Scope read = Scope.of("profile:read");
        Scope write = Scope.of("profile:write");

        // Roles
        Role admin = new Role("ADMIN", Set.of(read, write));
        Role userRole = new Role("USER", Set.of(read));

        Set<Role> roles = Set.of(admin, userRole);
        Set<Scope> scopes = Set.of(read, write);

        when(userAccountGateway.findByUsernameOrEmail(username))
                .thenReturn(Optional.of(user));

        when(roleProvider.resolveRoles(username)).thenReturn(roles);
        when(scopePolicy.resolveScopes(roles)).thenReturn(scopes);

        // Act
        MeResult result = meService.me(username);

        // Assert
        assertThat(result.username()).isEqualTo("lanny");
        assertThat(result.roles())
                .containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_USER");
        assertThat(result.scopes())
                .containsExactlyInAnyOrder("profile:read", "profile:write");
    }

    @Test
    @DisplayName("me() → should throw UserNotFoundException when user does not exist")
    void testShouldThrowWhenUserNotFound() {

        when(userAccountGateway.findByUsernameOrEmail("ghost"))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> meService.me("ghost"))
                .isInstanceOf(UserNotFoundException.class)
                .hasMessage("ghost");

        verifyNoInteractions(roleProvider, scopePolicy);
    }

    @Test
    @DisplayName("me() → handles empty role set gracefully")
    void testShouldHandleEmptyRoles() {

        String username = "lanny";
        User user = buildUser();

        when(userAccountGateway.findByUsernameOrEmail(username))
                .thenReturn(Optional.of(user));

        when(roleProvider.resolveRoles(username))
                .thenReturn(Set.of());

        when(scopePolicy.resolveScopes(Set.of()))
                .thenReturn(Set.of());

        MeResult result = meService.me(username);

        assertThat(result.roles()).isEmpty();
        assertThat(result.scopes()).isEmpty();
    }

    @Test
    @DisplayName("me() → handles empty scope set even when roles exist")
    void testShouldHandleEmptyScopes() {

        String username = "lanny";
        User user = buildUser();

        Scope read = Scope.of("profile:read");

        Role admin = new Role("ADMIN", Set.of(read));
        Set<Role> roles = Set.of(admin);

        when(userAccountGateway.findByUsernameOrEmail(username))
                .thenReturn(Optional.of(user));

        when(roleProvider.resolveRoles(username))
                .thenReturn(roles);

        when(scopePolicy.resolveScopes(roles))
                .thenReturn(Set.of());

        MeResult result = meService.me(username);

        assertThat(result.roles()).containsExactly("ROLE_ADMIN");
        assertThat(result.scopes()).isEmpty();
    }
}
