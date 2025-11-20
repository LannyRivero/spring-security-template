package com.lanny.spring_security_template.infrastructure.persistence.jpa.repository;

import com.lanny.spring_security_template.infrastructure.persistence.jpa.entity.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.List;

public interface RefreshTokenJpaRepository extends JpaRepository<RefreshTokenEntity, Long> {

    Optional<RefreshTokenEntity> findByJti(String jti);

    List<RefreshTokenEntity> findByUsername(String username);

    void deleteByJti(String jti);

    void deleteByUsername(String username);
}

