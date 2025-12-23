package com.lanny.spring_security_template.infrastructure.persistence.jpa;

import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.infrastructure.persistence.jpa.entity.RefreshTokenEntity;
import com.lanny.spring_security_template.infrastructure.persistence.jpa.repository.RefreshTokenJpaRepository;
import com.lanny.spring_security_template.infrastructure.security.util.TokenHashUtil;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

/**
 * JPA implementation of {@link RefreshTokenStore}.
 *
 * <p>
 * This adapter provides a <b>banking-grade</b> refresh token persistence model
 * based on:
 * </p>
 *
 * <ul>
 * <li>Hashed JWT IDs (JTI) — no clear-text tokens stored</li>
 * <li>Single-use (one-time) refresh tokens</li>
 * <li>Atomic consumption to prevent replay attacks</li>
 * <li>Database-enforced uniqueness</li>
 * </ul>
 *
 * <h2>Concurrency guarantees</h2>
 * <ul>
 * <li>Concurrent refresh attempts → only one succeeds</li>
 * <li>Double-spend prevented at database level</li>
 * <li>No reliance on transaction isolation alone</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>{@code exists()} is intentionally NOT supported</li>
 * <li>Refresh tokens are consumed, not checked</li>
 * <li>This class is transactional by design</li>
 * </ul>
 */
@Component
@RequiredArgsConstructor
@Transactional
public class RefreshTokenStoreJpa implements RefreshTokenStore {

    private final RefreshTokenJpaRepository repo;

    /**
     * Stores a new refresh token session.
     *
     * @param username  token owner
     * @param jti       refresh token JWT ID
     * @param issuedAt  issuance timestamp
     * @param expiresAt expiration timestamp
     */
    @Override
    public void save(String username, String jti, Instant issuedAt, Instant expiresAt) {

        RefreshTokenEntity entity = java.util.Objects.requireNonNull(
                RefreshTokenEntity.builder()
                        .username(username)
                        .jtiHash(TokenHashUtil.hashJti(jti))
                        .issuedAt(issuedAt)
                        .expiresAt(expiresAt)
                        .revoked(false)
                        .build(),
                "RefreshTokenEntity must not be null");

        repo.save(entity);
    }

    /**
     * Atomically consumes (revokes) a refresh token.
     *
     * <p>
     * This method guarantees that:
     * </p>
     * <ul>
     * <li>The refresh token can be used only once</li>
     * <li>Concurrent attempts result in a single success</li>
     * </ul>
     *
     * @param jti refresh token JWT ID
     * @return {@code true} if the token was successfully consumed,
     *         {@code false} otherwise
     */
    @Override
    public boolean consume(String jti) {
        String hash = TokenHashUtil.hashJti(jti);
        return repo.revokeByHash(hash) == 1;
    }

    /**
     * Deletes all refresh tokens for a given user.
     *
     * @param username target user
     */
    @Override
    public void deleteAllForUser(String username) {
        repo.deleteByUsername(username);
    }

    /**
     * Returns all active refresh token hashes for a user.
     *
     * <p>
     * Intended for auditing or administrative purposes.
     * </p>
     */
    @Override
    public List<String> findAllForUser(String username) {
        return repo.findByUsername(username)
                .stream()
                .map(RefreshTokenEntity::getJtiHash)
                .toList();
    }
}
