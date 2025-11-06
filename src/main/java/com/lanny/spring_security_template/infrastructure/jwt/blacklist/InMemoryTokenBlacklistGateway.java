package com.lanny.spring_security_template.infrastructure.jwt.blacklist;

import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
@Profile({ "dev", "test" })
public class InMemoryTokenBlacklistGateway implements TokenBlacklistGateway {
    private final Map<String, Instant> revoked = new ConcurrentHashMap<>();

    @Override
    public boolean isRevoked(String jti) {
        var exp = revoked.get(jti);
        if (exp == null)
            return false;
        if (exp.isBefore(Instant.now())) {
            revoked.remove(jti);
            return false;
        }
        return true;
    }

    @Override
    public void revoke(String jti, Instant exp) {
        revoked.put(jti, exp);
    }
}
