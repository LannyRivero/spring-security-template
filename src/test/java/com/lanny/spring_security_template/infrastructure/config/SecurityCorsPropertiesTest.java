package com.lanny.spring_security_template.infrastructure.config;

import static org.assertj.core.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationPropertiesBindException;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class SecurityCorsPropertiesTest {

    private final ApplicationContextRunner context = new ApplicationContextRunner()
            .withConfiguration(
                    org.springframework.boot.autoconfigure.AutoConfigurations.of(
                            ConfigurationPropertiesAutoConfiguration.class))
            .withUserConfiguration(WebCommonConfig.class);

    @Test
    @DisplayName("testShouldBindSecurityCorsPropertiesWhenConfigurationIsValid")
    void testShouldBindSecurityCorsPropertiesWhenConfigurationIsValid() {

        context.withPropertyValues(
                "security.cors.allowed-origins[0]=http://localhost:3000",
                "security.cors.allowed-methods=GET,POST",
                "security.cors.allowed-headers=Authorization,Content-Type",
                "security.cors.exposed-headers=X-Correlation-Id",
                "security.cors.allow-credentials=true").run(ctx -> {

                    assertThat(ctx).hasNotFailed();
                    SecurityCorsProperties props = ctx.getBean(SecurityCorsProperties.class);

                    assertThat(props.allowedOrigins()).containsExactly("http://localhost:3000");
                    assertThat(props.allowCredentials()).isTrue();
                });
    }

    @Test
    @DisplayName("testShouldLoadDefaultValuesWhenNoCorsPropertiesProvided")
    void testShouldLoadDefaultValuesWhenNoCorsPropertiesProvided() {

        context.run(ctx -> {
            assertThat(ctx).hasNotFailed();
            SecurityCorsProperties props = ctx.getBean(SecurityCorsProperties.class);

            assertThat(props.allowedOrigins()).containsExactly("*");
            assertThat(props.allowedMethods()).contains("GET", "POST");
            assertThat(props.allowCredentials()).isFalse();
        });
    }

    @Test
    @DisplayName("testShouldFailWhenCredentialsEnabledWithWildcardOrigin")
    void testShouldFailWhenCredentialsEnabledWithWildcardOrigin() {

        context.withPropertyValues(
                "security.cors.allowed-origins=*",
                "security.cors.allow-credentials=true").run(ctx -> {

                    assertThat(ctx).hasFailed();

                    Throwable failure = ctx.getStartupFailure();

                    assertThat(failure)
                            .isInstanceOf(ConfigurationPropertiesBindException.class);

                    assertThat(failure)
                            .hasRootCauseInstanceOf(IllegalArgumentException.class)
                            .rootCause()
                            .hasMessageContaining("Invalid CORS configuration");
                });
    }

    @Test
    @DisplayName("testShouldFailWhenRequiredFieldsAreEmpty")
    void testShouldFailWhenRequiredFieldsAreEmpty() {

        context.withPropertyValues(
                "security.cors.allowed-origins=",
                "security.cors.allowed-methods=").run(ctx -> {

                    assertThat(ctx).hasFailed();
                    assertThat(ctx.getStartupFailure())
                            .isInstanceOf(ConfigurationPropertiesBindException.class);
                });
    }
}
