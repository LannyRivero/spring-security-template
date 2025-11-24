package com.lanny.spring_security_template.infrastructure.jwt;

import com.lanny.spring_security_template.domain.time.ClockProvider;
import com.lanny.spring_security_template.testsupport.time.MutableClockProvider;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;
import com.lanny.spring_security_template.infrastructure.jwt.nimbus.JwtUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.*;

class JwtUtilsTimeTest {

    private JwtUtils newUtils(RsaKeyProvider keys, ClockProvider clock) {
        // usar properties DEFAULT (como las tienes en @ConfigurationProperties)
        SecurityJwtProperties props = new SecurityJwtProperties(
                "issuer-test",
                "access",
                "refresh",
                Duration.ofMinutes(15),
                Duration.ofDays(7),
                "RSA",
                false,
                List.of(),
                List.of(),
                1);

        return new JwtUtils(keys, props, clock);
    }

    @Test
    @DisplayName("Access token is valid before expiration")
    void tokenValidBeforeExpiration() {

        Instant start = Instant.parse("2030-01-01T00:00:00Z");
        MutableClockProvider clock = new MutableClockProvider(start);

        RsaKeyProvider keys = TestRsaKeys.generate();
        JwtUtils utils = newUtils(keys, clock);

        // TTL manual usando el overload generateToken()
        String token = utils.generateToken(
                "user123",
                List.of("ROLE_USER"),
                List.of("profile:read"),
                Duration.ofMinutes(5),
                false);

        JWTClaimsSet claims = utils.validateAndParse(token);
        assertThat(claims.getSubject()).isEqualTo("user123");
    }

    @Test
    @DisplayName("Access token expires when TTL is surpassed")
    void tokenExpiresAfterTTL() {

        Instant start = Instant.parse("2030-01-01T00:00:00Z");
        MutableClockProvider clock = new MutableClockProvider(start);

        RsaKeyProvider keys = TestRsaKeys.generate();
        JwtUtils utils = newUtils(keys, clock);

        String token = utils.generateToken(
                "user123",
                List.of(),
                List.of(),
                Duration.ofSeconds(60),
                false);

        // superamos la expiración
        clock.advanceSeconds(61);

        assertThatThrownBy(() -> utils.validateAndParse(token))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("expired");
    }

    @Test
    @DisplayName("Refresh token remains valid before expiration")
    void refreshValidBeforeExpiration() {

        Instant start = Instant.parse("2040-01-01T00:00:00Z");
        MutableClockProvider clock = new MutableClockProvider(start);

        RsaKeyProvider keys = TestRsaKeys.generate();
        JwtUtils utils = newUtils(keys, clock);

        String refresh = utils.generateToken(
                "userABC",
                List.of(),
                List.of(),
                Duration.ofHours(1),
                true);

        // avanzar 30 min (pero aún no expira)
        clock.advanceSeconds(1800);

        JWTClaimsSet claims = utils.validateAndParse(refresh);
        assertThat(claims.getSubject()).isEqualTo("userABC");
    }
}
