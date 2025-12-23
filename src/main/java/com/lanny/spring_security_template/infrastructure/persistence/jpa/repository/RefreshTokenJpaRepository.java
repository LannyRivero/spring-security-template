package com.lanny.spring_security_template.infrastructure.persistence.jpa.repository;

import com.lanny.spring_security_template.infrastructure.persistence.jpa.entity.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface RefreshTokenJpaRepository extends JpaRepository<RefreshTokenEntity, Long> {

    @Modifying
    @Query("""
            UPDATE RefreshTokenEntity r
                SET r.revoked = true
                WHERE r.jtiHash = :hash
                AND r.revoked = false
                """)
    int revokeByHash(@Param("hash") String hash);

    List<RefreshTokenEntity> findByUsername(String username);

    void deleteByUsername(String username);
}
