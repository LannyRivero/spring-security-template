package com.lanny.spring_security_template.infrastructure.scheduler;

import com.lanny.spring_security_template.application.auth.port.out.BlacklistCleanupGateway;
import com.lanny.spring_security_template.domain.time.ClockProvider;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
@Profile({ "prod", "demo" })
public class BlacklistCleanupScheduler {

    private final BlacklistCleanupGateway gateway;
    private final ClockProvider clockProvider;

    /**
     * Ejecuta cada 10 minutos:
     * - Busca tokens expirados (exp < now)
     * - Los elimina de la blacklist
     */
    @Scheduled(fixedDelay = 600_000) // 10 min
    public void cleanupExpiredTokens() {

        Instant now = clockProvider.now();
        List<String> expired = gateway.findExpired(now);

        if (expired.isEmpty()) {
            return;
        }

        expired.forEach(gateway::delete);

        log.info("[BLACKLIST CLEANUP] Removed {} expired tokens", expired.size());
    }
}
