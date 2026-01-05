package com.lanny.spring_security_template.infrastructure.adapter.usecase.transactional;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.lanny.spring_security_template.infrastructure.adapter.transactional.DevRegisterTransactionalAdapter;

/**
 * Minimal banking-grade context test.
 *
 * Verifies that DevRegisterTransactionalAdapter
 * is NOT loaded when prod profile is active,
 * without bootstrapping the full application
 * or unrelated adapters.
 */
class DevRegisterTransactionalAdapterProdContextTest {

    private final ApplicationContextRunner contextRunner =
            new ApplicationContextRunner()
                    .withUserConfiguration(TestConfig.class)
                    .withPropertyValues("spring.profiles.active=prod");

    @Test
    @DisplayName("DevRegisterTransactionalAdapter should NOT be loaded in PROD profile")
    void shouldNotLoadAdapterInProdProfile() {
        contextRunner.run(context ->
                assertThat(context.containsBean("devRegisterTransactionalAdapter"))
                        .isFalse()
        );
    }

    @Configuration
    @Import(DevRegisterTransactionalAdapter.class)
    static class TestConfig {
    }
}


