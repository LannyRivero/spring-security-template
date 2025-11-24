package com.lanny.spring_security_template.domain.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.*;

class RoleTest {

    @Test
    @DisplayName("Should normalize role name to uppercase")
    void shouldNormalizeRoleName() {
        Role role = new Role("admin", Set.of());

        assertThat(role.name()).isEqualTo("ROLE_ADMIN");
    }

    @Test
    @DisplayName("Should detect if role has a specific scope")
    void shouldDetectScope() {
        Scope read = Scope.of("simulation:read");
        Role role = new Role("USER", Set.of(read));

        assertThat(role.hasScope("simulation:read")).isTrue();
    }

    @Test
    @DisplayName("Should merge roles preserving distinct scopes")
    void shouldMergeRoles() {
        Scope a = Scope.of("user:read");
        Scope b = Scope.of("user:write");

        Role r1 = new Role("USER", Set.of(a));
        Role r2 = new Role("USER", Set.of(b));

        Role merged = r1.mergeWith(r2);

        assertThat(merged.scopes()).containsExactlyInAnyOrder(a, b);
    }
}
