package com.lanny.spring_security_template.infrastructure.jwt;


import com.lanny.spring_security_template.domain.time.ClockProvider;
import com.lanny.spring_security_template.testsupport.time.MutableClockProvider;
import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;
import com.lanny.spring_security_template.infrastructure.jwt.nimbus.JwtUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.*;

class JwtUtilsTimeTest {

    @Test
    @DisplayName("Access token should be valid before expiration time")
    void tokenShouldBeValidBeforeExpiration() {
        // Arrange
        Instant start = Instant.parse("2030-01-01T00:00:00Z");
        MutableClockProvider clock = new MutableClockProvider(start);

        RsaKeyProvider keys = TestRsaKeys.generate();
        JwtUtils utils = new JwtUtils(keys, clock);

        String token = utils.generateAccessToken("user123", "my-issuer", 300); // 5 min

        // Act + Assert
        assertThat(utils.validateAndParse(token)).isPresent();
    }

    @Test
    @DisplayName("Access token should expire exactly when TTL is surpassed")
    void tokenShouldExpireWhenSurpassedTTL() {
        // Arrange
        Instant start = Instant.parse("2030-01-01T00:00:00Z");
        MutableClockProvider clock = new MutableClockProvider(start);

        RsaKeyProvider keys = TestRsaKeys.generate();
        JwtUtils utils = new JwtUtils(keys, clock);

        String token = utils.generateAccessToken("user123", "my-issuer", 60); // 1 min TTL

        // Act — simulate time passing
        clock.advanceSeconds(61);

        // Assert
        assertThat(utils.validateAndParse(token)).isEmpty();
    }

    @Test
    @DisplayName("Refresh token should remain valid even after access token expiration")
    void refreshTokenShouldRemainValidAfterAccessExpiration() {
        // Arrange
        Instant start = Instant.parse("2040-01-01T00:00:00Z");
        MutableClockProvider clock = new MutableClockProvider(start);

        RsaKeyProvider keys = TestRsaKeys.generate();
        JwtUtils utils = new JwtUtils(keys, clock);

        String refreshToken = utils.generateRefreshToken("userABC", "issuer", 3600); // 1hr

        // Move time forward (but not enough to expire)
        clock.advanceSeconds(1800);

        // Act + Assert
        assertThat(utils.validateAndParse(refreshToken)).isPresent();
    }
}

