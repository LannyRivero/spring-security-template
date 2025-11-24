package com.lanny.spring_security_template.application.auth.query;

/**
 * Query object for retrieving authenticated user profile information.
 * 
 * <p>
 * This query encapsulates the data required by the "me" use case
 * following a CQRS-style separation between Commands (write operations)
 * and Queries (read operations).
 * </p>
 * 
 * <p>
 * The username is typically extracted from the authenticated principal
 * (JWT subject), not from the client request body.
 * </p>
 *
 * @param username the unique username (or user identifier) of the authenticated
 *                 user
 */
public record MeQuery(String username) {
}
