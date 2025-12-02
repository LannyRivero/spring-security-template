package com.lanny.spring_security_template.infrastructure.config.validation;

import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityJwtPropertiesValidatorTest {

    private final ApplicationContextRunner context = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    ConfigurationPropertiesAutoConfiguration.class))
            .withUserConfiguration(SecurityJwtTestConfig.class)
            .withPropertyValues(
                    "security.jwt.issuer=spring",
                    "security.jwt.access-ttl=PT10M",
                    "security.jwt.refresh-ttl=PT1H",
                    "security.jwt.algorithm=RSA");

    // -------------------------------------------
    // 1) Issuer empty
    // -------------------------------------------
    @Test
    @DisplayName("Should fail when issuer is blank")
    void testShouldFailWhenIssuerBlank() {

        context.withPropertyValues(
                "security.jwt.issuer=").run(ctx -> {

                    assertThat(ctx).hasFailed();

                    Throwable error = ctx.getStartupFailure().getCause().getCause();

                    assertThat(error)
                            .isInstanceOf(IllegalArgumentException.class)
                            .hasMessageContaining("issuer cannot be blank");
                });
    }

    // -------------------------------------------
    // 2) Access TTL < 5 min
    // -------------------------------------------
    @Test
    @DisplayName("Should fail when accessTtl is below minimum")
    void testShouldFailWhenAccessTtlTooShort() {

        context.withPropertyValues(
                "security.jwt.access-ttl=PT2M").run(ctx -> {

                    assertThat(ctx).hasFailed();

                    Throwable error = ctx.getStartupFailure().getCause().getCause();

                    assertThat(error)
                            .isInstanceOf(IllegalArgumentException.class)
                            .hasMessageContaining("accessTtl must be >= PT5M");
                });
    }

    // -------------------------------------------
    // 3) refresh <= access
    // -------------------------------------------
    @Test
    @DisplayName("Should fail when refreshTtl <= accessTtl")
    void testShouldFailWhenRefreshTtlNotGreaterThanAccessTtl() {

        context.withPropertyValues(
                "security.jwt.access-ttl=PT30M",
                "security.jwt.refresh-ttl=PT10M").run(ctx -> {

                    assertThat(ctx).hasFailed();

                    Throwable error = ctx.getStartupFailure().getCause().getCause();

                    assertThat(error)
                            .isInstanceOf(IllegalArgumentException.class)
                            .hasMessageContaining("refreshTtl must be greater than accessTtl");
                });
    }

    // -------------------------------------------
    // 4) Invalid scope
    // -------------------------------------------
    @Test
    @DisplayName("Should fail when invalid scope format is provided")
    void testShouldFailWhenInvalidScopeFormat() {

        context.withPropertyValues(
                "security.jwt.default-scopes=invalidScope").run(ctx -> {

                    assertThat(ctx).hasFailed();

                    Throwable error = ctx.getStartupFailure().getCause().getCause();

                    assertThat(error)
                            .isInstanceOf(IllegalArgumentException.class)
                            .hasMessageContaining("Invalid JWT scope");
                });
    }

    // -------------------------------------------
    // 5) Invalid role
    // -------------------------------------------
    @Test
    @DisplayName("Should fail when roles do not start with ROLE_")
    void testShouldFailWhenInvalidRoleFormat() {

        context.withPropertyValues(
                "security.jwt.default-roles=USER").run(ctx -> {

                    assertThat(ctx).hasFailed();

                    Throwable error = ctx.getStartupFailure().getCause().getCause();

                    assertThat(error)
                            .isInstanceOf(IllegalArgumentException.class)
                            .hasMessageContaining("roles must follow the pattern ROLE_XYZ");
                });
    }

    // -------------------------------------------
    // 6) Valid configuration (happy path)
    // -------------------------------------------
    @Test
    @DisplayName("Should load when configuration is valid")
    void testShouldLoadContextWithValidConfiguration() {

        context.withPropertyValues(
                "security.jwt.issuer=my-app",
                "security.jwt.access-ttl=PT10M",
                "security.jwt.refresh-ttl=PT1H",
                "security.jwt.algorithm=RSA",
                "security.jwt.default-roles=ROLE_USER",
                "security.jwt.default-scopes=read:users").run(ctx -> {

                    assertThat(ctx).hasNotFailed();

                    SecurityJwtProperties props = ctx.getBean(SecurityJwtProperties.class);

                    assertThat(props.issuer()).isEqualTo("my-app");
                    assertThat(props.accessTtl()).isEqualTo(Duration.ofMinutes(10));
                    assertThat(props.refreshTtl()).isEqualTo(Duration.ofHours(1));
                    assertThat(props.defaultRoles()).containsExactly("ROLE_USER");
                    assertThat(props.defaultScopes()).containsExactly("read:users");
                });
    }
}
