package com.lanny.spring_security_template.infrastructure.config;

import static org.assertj.core.api.Assertions.*;

import java.time.Duration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class JwtConfigTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(JwtConfig.class);

    // ================================================================
    @Test
    @DisplayName("testShouldLoadSecurityJwtPropertiesWhenJwtConfigIsEnabled")
    void testShouldLoadSecurityJwtPropertiesWhenJwtConfigIsEnabled() {

        contextRunner
                .withPropertyValues(
                        "security.jwt.issuer=test-issuer",
                        "security.jwt.access-audience=access-service",
                        "security.jwt.refresh-audience=refresh-service",
                        "security.jwt.access-ttl=PT45M",
                        "security.jwt.refresh-ttl=P14D",
                        "security.jwt.algorithm=HMAC",
                        "security.jwt.rotate-refresh-tokens=true",
                        "security.jwt.max-active-sessions=5")
                .run(context -> {

                    SecurityJwtProperties props = context.getBean(SecurityJwtProperties.class);

                    assertThat(props.issuer()).isEqualTo("test-issuer");
                    assertThat(props.accessAudience()).isEqualTo("access-service");
                    assertThat(props.refreshAudience()).isEqualTo("refresh-service");

                    assertThat(props.accessTtl().toString()).isEqualTo("PT45M");
                    assertThat(props.refreshTtl()).isEqualTo(Duration.ofDays(14));

                    assertThat(props.algorithm()).isEqualTo("HMAC");
                    assertThat(props.rotateRefreshTokens()).isTrue();

                    assertThat(props.maxActiveSessions()).isEqualTo(5);
                });
    }

    // ================================================================
    @Test
    @DisplayName("testShouldLoadDefaultsWhenNoPropertiesProvided")
    void testShouldLoadDefaultsWhenNoPropertiesProvided() {

        contextRunner.run(context -> {

            SecurityJwtProperties props = context.getBean(SecurityJwtProperties.class);

            assertThat(props.issuer()).isEqualTo("spring-security-template");
            assertThat(props.accessAudience()).isEqualTo("access");
            assertThat(props.refreshAudience()).isEqualTo("refresh");

            assertThat(props.accessTtl().toString()).isEqualTo("PT15M");
            assertThat(props.refreshTtl()).isEqualTo(Duration.ofDays(7));

            assertThat(props.algorithm()).isEqualTo("RSA");
            assertThat(props.rotateRefreshTokens()).isFalse();

            assertThat(props.defaultRoles()).isEmpty();
            assertThat(props.defaultScopes()).isEmpty();

            assertThat(props.maxActiveSessions()).isEqualTo(1);
        });
    }

    // ================================================================
    @Test
    @DisplayName("testShouldHaveEnableConfigurationPropertiesAnnotation")
    void testShouldHaveEnableConfigurationPropertiesAnnotation() {

        boolean hasAnnotation = JwtConfig.class
                .getAnnotation(org.springframework.boot.context.properties.EnableConfigurationProperties.class) != null;

        assertThat(hasAnnotation).isTrue();
    }
}
