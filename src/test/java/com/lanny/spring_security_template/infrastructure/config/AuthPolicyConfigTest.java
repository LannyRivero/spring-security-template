package com.lanny.spring_security_template.infrastructure.config;

import com.lanny.spring_security_template.application.auth.policy.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class AuthPolicyConfigTest {

    private final AuthPolicyConfig config = new AuthPolicyConfig();

    @Test
    @DisplayName("testShouldCreateTokenPolicyPropertiesFromProps")
    void testShouldCreateTokenPolicyPropertiesFromProps() {
        SecurityJwtProperties props = Mockito.mock(SecurityJwtProperties.class);
        Mockito.when(props.accessTtl()).thenReturn(Duration.ofMinutes(10));
        Mockito.when(props.refreshTtl()).thenReturn(Duration.ofDays(7));
        Mockito.when(props.issuer()).thenReturn("issuer");
        Mockito.when(props.accessAudience()).thenReturn("access");
        Mockito.when(props.refreshAudience()).thenReturn("refresh");

        TokenPolicyProperties bean = config.tokenPolicyProperties(props);

        assertThat(bean).isNotNull();
        assertThat(bean.accessTokenTtl()).isEqualTo(Duration.ofMinutes(10));
        assertThat(bean.refreshTokenTtl()).isEqualTo(Duration.ofDays(7));
        assertThat(bean.issuer()).isEqualTo("issuer");
        assertThat(bean.accessAudience()).isEqualTo("access");
        assertThat(bean.refreshAudience()).isEqualTo("refresh");
    }

    @Test
    @DisplayName("testShouldCreateRefreshTokenPolicy")
    void testShouldCreateRefreshTokenPolicy() {
        SecurityJwtProperties props = Mockito.mock(SecurityJwtProperties.class);
        Mockito.when(props.refreshAudience()).thenReturn("refresh");

        RefreshTokenPolicy policy = config.refreshTokenPolicy(props);

        assertThat(policy).isNotNull();
        assertThat(policy.expectedRefreshAudience()).isEqualTo("refresh");
    }

    @Test
    @DisplayName("testShouldCreateSessionPolicy")
    void testShouldCreateSessionPolicy() {
        SecurityJwtProperties props = Mockito.mock(SecurityJwtProperties.class);
        Mockito.when(props.maxActiveSessions()).thenReturn(3);

        SessionPolicy policy = config.sessionPolicy(props);

        assertThat(policy).isNotNull();
        assertThat(policy.maxSessionsPerUser()).isEqualTo(3);
    }

    @Test
    @DisplayName("testShouldCreateRotationPolicy")
    void testShouldCreateRotationPolicy() {
        SecurityJwtProperties props = Mockito.mock(SecurityJwtProperties.class);
        Mockito.when(props.rotateRefreshTokens()).thenReturn(true);

        RotationPolicy policy = config.rotationPolicy(props);

        assertThat(policy).isNotNull();
        assertThat(policy.isRotationEnabled()).isTrue();
    }
}
