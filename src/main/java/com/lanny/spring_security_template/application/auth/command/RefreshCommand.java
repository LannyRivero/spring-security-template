package com.lanny.spring_security_template.application.auth.command;

/**
 * Command for the Refresh Token use case.
 *
 * <p>
 * This command wraps the raw refresh token obtained from the client.
 * No parsing or validation is performed here. The RefreshService is
 * responsible for verifying the token's signature, expiration, audience,
 * and revocation status (blacklist + refresh store).
 * </p>
 */
public record RefreshCommand(
        String refreshToken) {
}
