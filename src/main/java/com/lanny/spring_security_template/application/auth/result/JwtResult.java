package com.lanny.spring_security_template.application.auth.result;

import java.time.Instant;

/**
 * Result object returned by authentication and token-refresh use cases.
 *
 * <p>
 * It represents the output of the Auth flow in the application layer,
 * independently of any transport protocol (HTTP, REST, WebFlux, GraphQL, etc.).
 * Controllers or handlers are responsible for converting this into DTOs
 * appropriate for the API layer.
 * </p>
 *
 * <p>
 * The {@code expiresAt} field corresponds to the expiration instant of the
 * newly issued access token (the {@code exp} claim in the JWT). The refresh
 * token
 * typically has a longer lifetime and is managed separately.
 * </p>
 *
 * @param accessToken  Newly issued access token (JWT)
 * @param refreshToken Newly issued or original refresh token (depending on
 *                     rotation policy)
 * @param expiresAt    Instant when the access token expires (UTC)
 */
public record JwtResult(
        String accessToken,
        String refreshToken,
        Instant expiresAt) {
}
