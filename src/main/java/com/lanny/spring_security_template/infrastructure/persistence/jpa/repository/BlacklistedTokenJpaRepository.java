package com.lanny.spring_security_template.infrastructure.persistence.jpa.repository;

import com.lanny.spring_security_template.infrastructure.persistence.jpa.entity.BlacklistedTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;

public interface BlacklistedTokenJpaRepository extends JpaRepository<BlacklistedTokenEntity, Long> {

    List<BlacklistedTokenEntity> findByExpiresAtBefore(Instant now);

    void deleteByJti(String jti);
}
