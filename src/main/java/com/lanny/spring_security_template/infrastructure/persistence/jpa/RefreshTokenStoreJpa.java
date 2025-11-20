package com.lanny.spring_security_template.infrastructure.persistence.jpa;

import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.infrastructure.persistence.jpa.entity.RefreshTokenEntity;
import com.lanny.spring_security_template.infrastructure.persistence.jpa.repository.RefreshTokenJpaRepository;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

@Component
public class RefreshTokenStoreJpa implements RefreshTokenStore {

    private final RefreshTokenJpaRepository repo;

    public RefreshTokenStoreJpa(RefreshTokenJpaRepository repo) {
        this.repo = repo;
    }

    @Override
    public void save(String username, String jti, Instant issuedAt, Instant expiresAt) {
        RefreshTokenEntity entity = RefreshTokenEntity.builder()
                .username(username)
                .jti(jti)
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .build();
        if (entity != null) {
            repo.save(entity);
        }
    }

    @Override
    public boolean exists(String jti) {
        return repo.findByJti(jti).isPresent();
    }

    @Override
    public void delete(String jti) {
        repo.deleteByJti(jti);
    }

    @Override
    public void deleteAllForUser(String username) {
        repo.deleteByUsername(username);
    }

    @Override
    public List<String> findAllForUser(String username) {
        return repo.findByUsername(username)
                .stream()
                .map(RefreshTokenEntity::getJti)
                .toList();
    }
}
