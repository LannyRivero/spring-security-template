package com.lanny.spring_security_template.domain.model;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.exception.UserLockedException;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.domain.valueobject.EmailAddress;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;
import com.lanny.spring_security_template.domain.valueobject.Username;

class UserTest {

    private static final String VALID_HASH = "$2a$10$abcdefghijklmnopqrstuv123456789012345678901234567890";

    private final PasswordHasher fakeHasher = new PasswordHasher() {
        @Override
        public String hash(String raw) {
            return VALID_HASH;
        }

        @Override
        public boolean matches(String rawPassword, String hashedPassword) {
            return hashedPassword.equals(VALID_HASH) && rawPassword.equals("secret");
        }
    };

    private User buildActiveUser() {
        return User.createNew(
                Username.of("john"),
                EmailAddress.of("john@example.com"),
                PasswordHash.of(VALID_HASH),
                List.of(Role.from("ADMIN")),
                List.of(Scope.of("profile:read")));
    }

    // ========================================================================
    // TESTS
    // ========================================================================

    @Test
    @DisplayName("User.createNew should construct a valid aggregate")
    void testShouldCreateNewUser() {
        User user = buildActiveUser();

        assertNotNull(user.id());
        assertEquals("john", user.username().value());
        assertEquals("john@example.com", user.email().value());
        assertEquals(1, user.roles().size());
        assertEquals(1, user.scopes().size());
        assertTrue(user.status().isActive());
    }

    @Test
    @DisplayName("User.verifyPassword should accept valid password")
    void testShouldVerifyValidPassword() {
        User user = buildActiveUser();

        assertDoesNotThrow(() -> user.verifyPassword("secret", fakeHasher));
    }

    @Test
    @DisplayName("User.verifyPassword should reject invalid password")
    void verifyInvalidPassword() {
        User user = buildActiveUser();

        assertThrows(InvalidCredentialsException.class,
                () -> user.verifyPassword("wrong", fakeHasher));
    }

    @Test
    @DisplayName("User should forbid authentication when LOCKED")
    void testShouldLockedUserCannotAuthenticate() {
        User locked = User.rehydrate(
                buildActiveUser().id(),
                buildActiveUser().username(),
                buildActiveUser().email(),
                PasswordHash.of(VALID_HASH),
                UserStatus.LOCKED,
                buildActiveUser().roles(),
                buildActiveUser().scopes());

        assertThrows(UserLockedException.class, locked::ensureCanAuthenticate);
    }

    @Test
@DisplayName("withChangedPassword should return a new instance with updated password only")
void testShouldChangePassword() {

    User user = buildActiveUser();

    PasswordHash newHash = PasswordHash.of(
            "$2a$10$BBBBBBBBBBBBBBBBBBBBBB123456789012345678901234567890"
    );

    User updated = user.withChangedPassword(newHash);

    assertEquals(user.id(), updated.id());

    assertEquals(newHash, updated.passwordHash());
    assertNotEquals(user.passwordHash(), updated.passwordHash());

    assertEquals(user.username(), updated.username());
    assertEquals(user.email(), updated.email());
    assertEquals(user.roles(), updated.roles());
    assertEquals(user.scopes(), updated.scopes());

    assertNotSame(user, updated);
}


    @Test
    @DisplayName("authorities() should return ROLE_ and SCOPE_ entries")
    void testShouldReturnRoleAndScopeAuthorities() {
        User user = buildActiveUser();

        Set<String> authorities = user.authorities();

        assertTrue(authorities.contains("ROLE_ADMIN"));
        assertTrue(authorities.contains("SCOPE_profile:read"));
    }

    @Test
    @DisplayName("authorities(policy) should expand scopes using ScopePolicy")
    void testShouldExpandScopesUsingPolicy() {
        User user = buildActiveUser();

        ScopePolicy policy = roles -> Set.of(
                Scope.of("profile:read"),
                Scope.of("profile:write"));

        Set<String> authorities = user.authorities(policy);

        assertTrue(authorities.contains("ROLE_ADMIN"));
        assertTrue(authorities.contains("SCOPE_profile:read"));
        assertTrue(authorities.contains("SCOPE_profile:write"));
    }
}
