package com.lanny.spring_security_template.infrastructure.config;

import static org.assertj.core.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationPropertiesBindException;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

class RateLimitingPropertiesTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    ConfigurationPropertiesAutoConfiguration.class))
            .withUserConfiguration(RateLimitingPropertiesConfig.class)
            .withPropertyValues(
                    "rate-limiting.enabled=true",
                    "rate-limiting.strategy=IP_USER",
                    "rate-limiting.maxAttempts=5",
                    "rate-limiting.window=60",
                    "rate-limiting.blockSeconds=300",
                    "rate-limiting.retryAfter=60",
                    "rate-limiting.loginPath=/api/v1/auth/login");

    @Configuration
    @EnableConfigurationProperties(RateLimitingProperties.class)
    static class RateLimitingPropertiesConfig {
    }

    // ---------------------------------------------------------------
    @Test
    @DisplayName("testShouldBindRateLimitingPropertiesWhenValidConfiguration")
    void testShouldBindRateLimitingPropertiesWhenValidConfiguration() {
        contextRunner.run(ctx -> {
            assertThat(ctx).hasNotFailed();

            RateLimitingProperties props = ctx.getBean(RateLimitingProperties.class);

            assertThat(props.enabled()).isTrue();
            assertThat(props.strategy()).isEqualTo("IP_USER");
            assertThat(props.maxAttempts()).isEqualTo(5);
            assertThat(props.window()).isEqualTo(60);
            assertThat(props.blockSeconds()).isEqualTo(300);
            assertThat(props.retryAfter()).isEqualTo(60);
            assertThat(props.loginPath()).isEqualTo("/api/v1/auth/login");
        });
    }

    // ---------------------------------------------------------------
    @Test
    @DisplayName("testShouldFailValidationWhenStrategyIsBlank")
    void testShouldFailValidationWhenStrategyIsBlank() {

        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        ConfigurationPropertiesAutoConfiguration.class))
                .withUserConfiguration(RateLimitingPropertiesConfig.class)
                .withPropertyValues(
                        "rate-limiting.enabled=true",
                        "rate-limiting.strategy=",
                        "rate-limiting.maxAttempts=5",
                        "rate-limiting.window=60",
                        "rate-limiting.blockSeconds=300",
                        "rate-limiting.retryAfter=60",
                        "rate-limiting.loginPath=/api/v1/auth/login")
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    assertThat(ctx.getStartupFailure())
                            .isInstanceOf(ConfigurationPropertiesBindException.class);

                });
    }

    // ---------------------------------------------------------------
    @Test
    @DisplayName("testShouldFailValidationWhenNumericValuesAreZeroOrNegative")
    void testShouldFailValidationWhenNumericValuesAreZeroOrNegative() {

        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        ConfigurationPropertiesAutoConfiguration.class))
                .withUserConfiguration(RateLimitingPropertiesConfig.class)
                .withPropertyValues(
                        "rate-limiting.enabled=true",
                        "rate-limiting.strategy=IP",
                        "rate-limiting.maxAttempts=0",
                        "rate-limiting.window=-1",
                        "rate-limiting.blockSeconds=0",
                        "rate-limiting.retryAfter=-5",
                        "rate-limiting.loginPath=/api/v1/auth/login")
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    assertThat(ctx.getStartupFailure())
                            .isInstanceOf(ConfigurationPropertiesBindException.class);

                });
    }
}
