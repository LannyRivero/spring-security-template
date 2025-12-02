package com.lanny.spring_security_template.infrastructure.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityJwtPropertiesTest {

    private final ApplicationContextRunner context = new ApplicationContextRunner()
            .withConfiguration(
                    org.springframework.boot.autoconfigure.AutoConfigurations.of(
                            ConfigurationPropertiesAutoConfiguration.class))
            .withUserConfiguration(JwtConfig.class);

    @Test
    @DisplayName("testShouldBindSecurityJwtPropertiesWhenConfigurationIsValid")
    void testShouldBindSecurityJwtPropertiesWhenConfigurationIsValid() {

        context.withPropertyValues(
                "security.jwt.issuer=my-auth-server",
                "security.jwt.access-audience=access-service",
                "security.jwt.refresh-audience=refresh-service",
                "security.jwt.access-ttl=PT1H",
                "security.jwt.refresh-ttl=P14D",
                "security.jwt.algorithm=HMAC",
                "security.jwt.rotate-refresh-tokens=true",
                "security.jwt.default-roles[0]=ROLE_USER",
                "security.jwt.default-scopes[0]=profile:read",
                "security.jwt.max-active-sessions=5").run(ctx -> {

                    assertThat(ctx).hasNotFailed();

                    SecurityJwtProperties props = ctx.getBean(SecurityJwtProperties.class);

                    assertThat(props.issuer()).isEqualTo("my-auth-server");
                    assertThat(props.accessAudience()).isEqualTo("access-service");
                    assertThat(props.refreshAudience()).isEqualTo("refresh-service");
                    assertThat(props.accessTtl()).isEqualTo(Duration.ofHours(1));
                    assertThat(props.refreshTtl()).isEqualTo(Duration.ofDays(14));
                    assertThat(props.algorithm()).isEqualTo("HMAC");
                    assertThat(props.rotateRefreshTokens()).isTrue();
                    assertThat(props.defaultRoles()).containsExactly("ROLE_USER");
                    assertThat(props.defaultScopes()).containsExactly("profile:read");
                    assertThat(props.maxActiveSessions()).isEqualTo(5);
                });
    }

    @Test
    @DisplayName("testShouldLoadDefaultValuesWhenNoJwtPropertiesProvided")
    void testShouldLoadDefaultValuesWhenNoJwtPropertiesProvided() {

        context.run(ctx -> {

            assertThat(ctx).hasNotFailed();

            SecurityJwtProperties props = ctx.getBean(SecurityJwtProperties.class);

            assertThat(props.issuer()).isEqualTo("spring-security-template");
            assertThat(props.accessAudience()).isEqualTo("access");
            assertThat(props.refreshAudience()).isEqualTo("refresh");
            assertThat(props.accessTtl()).isEqualTo(Duration.ofMinutes(15));
            assertThat(props.refreshTtl()).isEqualTo(Duration.ofDays(7));
            assertThat(props.algorithm()).isEqualTo("RSA");
            assertThat(props.rotateRefreshTokens()).isFalse();
            assertThat(props.defaultRoles()).isEmpty();
            assertThat(props.defaultScopes()).isEmpty();
            assertThat(props.maxActiveSessions()).isEqualTo(1);
        });
    }

    @Test
    @DisplayName("testShouldSupportEmptyDefaultRolesAndScopes")
    void testShouldSupportEmptyDefaultRolesAndScopes() {

        context.withPropertyValues(
                "security.jwt.default-roles=",
                "security.jwt.default-scopes=").run(ctx -> {

                    assertThat(ctx).hasNotFailed();

                    SecurityJwtProperties props = ctx.getBean(SecurityJwtProperties.class);

                    assertThat(props.defaultRoles()).isEmpty();
                    assertThat(props.defaultScopes()).isEmpty();
                });
    }
}
