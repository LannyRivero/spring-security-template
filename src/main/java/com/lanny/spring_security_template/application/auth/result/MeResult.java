package com.lanny.spring_security_template.application.auth.result;

import java.util.List;

/**
 * Result object representing the authenticated user's profile.
 *
 * <p>
 * Returned by the {@code /auth/me} use case. Contains strictly
 * the identity and authorization attributes of the current user,
 * without exposing internal or sensitive information.
 * </p>
 *
 * <p>
 * The roles and scopes listed here are those resolved by the
 * RoleProvider and ScopePolicy, ensuring that the final authorization
 * model is centrally managed and consistent across the application.
 * </p>
 *
 * @param userId   Stable identifier of the authenticated user (domain UserId)
 * @param username Normalized username
 * @param roles    List of assigned role names (e.g., "ADMIN", "USER")
 * @param scopes   Fine-grained permission names (e.g., "profile:read")
 */
public record MeResult(
        String userId,
        String username,
        List<String> roles,
        List<String> scopes) {
}
