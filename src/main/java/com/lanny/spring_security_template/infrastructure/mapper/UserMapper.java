package com.lanny.spring_security_template.infrastructure.mapper;

import java.util.List;
import java.util.Objects;

import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.domain.model.Role;
import com.lanny.spring_security_template.domain.model.Scope;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.model.UserStatus;
import com.lanny.spring_security_template.domain.valueobject.EmailAddress;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;
import com.lanny.spring_security_template.domain.valueobject.UserId;
import com.lanny.spring_security_template.domain.valueobject.Username;

/**
 * Maps persistence-layer raw data (String roles/scopes)
 * to rich domain Value Objects and aggregates.
 *
 * This mapper belongs exclusively to the infrastructure layer.
 */
@Component
public class UserMapper {

    // ========================================================================
    // STRING → VALUE OBJECTS
    // ========================================================================

    public List<Role> toRoleList(List<String> roles) {
        Objects.requireNonNull(roles);
        return roles.stream()
                .map(Role::from)
                .toList();
    }

    public List<Scope> toScopeList(List<String> scopes) {
        Objects.requireNonNull(scopes);
        return scopes.stream()
                .map(Scope::of)
                .toList();
    }

    // ========================================================================
    // VALUE OBJECTS → STRING
    // ========================================================================

    public List<String> toRoleNames(List<Role> roles) {
        return roles.stream()
                .map(Role::name)
                .toList();
    }

    public List<String> toScopeNames(List<Scope> scopes) {
        return scopes.stream()
                .map(Scope::name)
                .toList();
    }

    // ========================================================================
    // ENTITY → DOMAIN
    // ========================================================================

    public User toDomain(
            String id,
            String username,
            String email,
            String passwordHash,
            UserStatus status,
            List<String> roles,
            List<String> scopes) {
        return User.rehydrate(
                UserId.from(id),
                Username.of(username),
                EmailAddress.of(email),
                PasswordHash.of(passwordHash),
                status,
                toRoleList(roles),
                toScopeList(scopes));
    }

    // ========================================================================
    // DOMAIN → PERSISTENCE (strings)
    // ========================================================================

    public String userId(User user) {
        return user.id().value().toString();
    }

    public List<String> roleNames(User user) {
        return toRoleNames(user.roles());
    }

    public List<String> scopeNames(User user) {
        return toScopeNames(user.scopes());
    }
}
