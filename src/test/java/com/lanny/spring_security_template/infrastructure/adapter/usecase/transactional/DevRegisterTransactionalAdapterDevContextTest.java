package com.lanny.spring_security_template.infrastructure.adapter.usecase.transactional;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import com.lanny.spring_security_template.infrastructure.transactional.DevRegisterTransactionalAdapter;

/**
 * Banking-grade context test.
 *
 * Ensures that DevRegisterTransactionalAdapter
 * IS available when running with the 'dev' profile.
 */
@SpringBootTest
@ActiveProfiles("dev")
class DevRegisterTransactionalAdapterDevContextTest {

    @Autowired(required = false)
    private DevRegisterTransactionalAdapter adapter;

    @Test
    @DisplayName("DevRegisterTransactionalAdapter should be loaded in DEV profile")
    void shouldLoadAdapterInDevProfile() {
        assertThat(adapter).isNotNull();
    }
}

