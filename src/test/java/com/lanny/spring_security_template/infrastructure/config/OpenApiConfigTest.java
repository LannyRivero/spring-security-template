package com.lanny.spring_security_template.infrastructure.config;

import static org.assertj.core.api.Assertions.assertThat;

import io.swagger.v3.oas.models.OpenAPI;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.boot.test.context.runner.ApplicationContextRunner;

public class OpenApiConfigTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(OpenApiConfig.class);

    // ----------------------------------------------------------------------
    @Test
    @DisplayName("testShouldCreateOpenApiBeanWithDefaultLocalhostServerWhenNoProfileOrProperty")
    void testShouldCreateOpenApiBeanWithDefaultLocalhostServerWhenNoProfileOrProperty() {

        contextRunner.run(ctx -> {
            OpenAPI api = ctx.getBean(OpenAPI.class);

            assertThat(api).isNotNull();
            assertThat(api.getServers()).hasSize(1);

            String url = api.getServers().get(0).getUrl();
            assertThat(url).isEqualTo("http://localhost:8080");
        });
    }

    // ----------------------------------------------------------------------
    @Test
    @DisplayName("testShouldUsePropertyServerUrlWhenOpenApiServerUrlIsProvided")
    void testShouldUsePropertyServerUrlWhenOpenApiServerUrlIsProvided() {

        contextRunner
                .withPropertyValues("openapi.server-url=https://external.example.com")
                .run(ctx -> {

                    OpenAPI api = ctx.getBean(OpenAPI.class);

                    assertThat(api.getServers()).hasSize(1);

                    String url = api.getServers().get(0).getUrl();
                    assertThat(url).isEqualTo("https://external.example.com");
                });
    }

    // ----------------------------------------------------------------------
    @Test
    @DisplayName("testShouldUseProdServerUrlWhenProfileIsProdAndNoPropertyProvided")
    void testShouldUseProdServerUrlWhenProfileIsProdAndNoPropertyProvided() {

        contextRunner
                .withPropertyValues("spring.profiles.active=prod")
                .run(ctx -> {

                    OpenAPI api = ctx.getBean(OpenAPI.class);

                    assertThat(api.getServers()).hasSize(1);

                    String url = api.getServers().get(0).getUrl();
                    assertThat(url).isEqualTo("https://api.springtemplate.dev");
                });
    }

    // ----------------------------------------------------------------------
    @Test
    @DisplayName("testShouldUseTestServerUrlWhenProfileIsTest")
    void testShouldUseTestServerUrlWhenProfileIsTest() {

        contextRunner
                .withPropertyValues("spring.profiles.active=test")
                .run(ctx -> {

                    OpenAPI api = ctx.getBean(OpenAPI.class);

                    assertThat(api.getServers()).hasSize(1);

                    String url = api.getServers().get(0).getUrl();
                    assertThat(url).isEqualTo("http://localhost:8081");
                });
    }

    // ----------------------------------------------------------------------
    @Test
    @DisplayName("testShouldPrioritizePropertyOverProfile")
    void testShouldPrioritizePropertyOverProfile() {

        contextRunner
                .withPropertyValues(
                        "spring.profiles.active=prod",
                        "openapi.server-url=https://override.url")
                .run(ctx -> {

                    OpenAPI api = ctx.getBean(OpenAPI.class);

                    assertThat(api.getServers()).hasSize(1);

                    String url = api.getServers().get(0).getUrl();
                    assertThat(url).isEqualTo("https://override.url");
                });
    }
}
