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
                false);

        return new JwtUtils(keys, props, clock);
    }

    @Test
    @DisplayName("Access token is valid before expiration")
    void tokenValidBeforeExpiration() {

        Instant start = Instant.parse("2030-01-01T00:00:00Z");
        MutableClockProvider clock = new MutableClockProvider(start);

        RsaKeyProvider keys = TestRsaKeys.generate();
        JwtUtils utils = newUtils(keys, clock);

        // Use the public generateAccessToken method instead
        String token = utils.generateAccessToken(
                "user123",
                List.of("ROLE_USER"),
                List.of("profile:read"),
                Duration.ofMinutes(15));

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

        // Use generateAccessToken (it will use the default 15min TTL from props)
        String token = utils.generateAccessToken(
                "user123",
                List.of(),
                List.of(),
                Duration.ofMinutes(15));

        // Advance past the default 15 minutes expiration
        clock.advanceSeconds(901); // 15min + 1sec

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

        // Use generateRefreshToken
        String refresh = utils.generateRefreshToken("userABC", Duration.ofDays(7));

        // Advance 30 min (but default refresh TTL is 7 days, so still valid)
        clock.advanceSeconds(1800);

        JWTClaimsSet claims = utils.validateAndParse(refresh);
        assertThat(claims.getSubject()).isEqualTo("userABC");
    }
}
