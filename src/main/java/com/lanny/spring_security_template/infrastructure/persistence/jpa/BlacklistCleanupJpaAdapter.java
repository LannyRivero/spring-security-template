package com.lanny.spring_security_template.infrastructure.persistence.jpa;

import com.lanny.spring_security_template.application.auth.port.out.BlacklistCleanupGateway;
import com.lanny.spring_security_template.infrastructure.persistence.jpa.repository.BlacklistedTokenJpaRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

@Component
@Profile("prod")
@RequiredArgsConstructor
public class BlacklistCleanupJpaAdapter implements BlacklistCleanupGateway {

    private final BlacklistedTokenJpaRepository repo;

    @Override
    public List<String> findExpired(Instant now) {
        return repo.findByExpiresAtBefore(now)
                .stream()
                .map(token -> token.getJti())
                .toList();
    }

    @Override
    public void delete(String jti) {
        repo.deleteByJti(jti);
    }
}
