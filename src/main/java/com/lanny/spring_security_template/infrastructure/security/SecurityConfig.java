package com.lanny.spring_security_template.infrastructure.security;

import com.lanny.spring_security_template.infrastructure.config.SecurityCorsProperties;
import com.lanny.spring_security_template.infrastructure.security.filter.*;
import com.lanny.spring_security_template.infrastructure.security.handler.*;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.*;

/**
 * Central Spring Security configuration for the application.
 *
 * <p>
 * This configuration defines a <b>stateless, JWT-based security model</b>
 * designed for REST APIs and microservices. Session-based authentication
 * and CSRF protection are explicitly disabled.
 * </p>
 *
 * <h2>Security model</h2>
 * <ul>
 * <li>Authentication is performed using <b>JWT access tokens</b>.</li>
 * <li>Authorization is enforced via roles and scopes, evaluated at
 * both filter and method levels.</li>
 * <li>No HTTP session is created or used
 * ({@link SessionCreationPolicy#STATELESS}).</li>
 * </ul>
 *
 * <h2>Public endpoints</h2>
 * <ul>
 * <li><b>Actuator:</b> health and info endpoints only.</li>
 * <li><b>Authentication:</b> login and refresh endpoints.</li>
 * <li><b>OpenAPI / Swagger:</b> enabled for API documentation.</li>
 * </ul>
 *
 * <h2>Filter chain</h2>
 * <p>
 * The filter order is explicitly defined to ensure predictable and secure
 * request processing:
 * </p>
 * <ol>
 * <li>{@link CorrelationIdFilter} – assigns a correlation ID for logging
 * and tracing.</li>
 * <li>{@link SecurityHeadersFilter} – applies HTTP security headers.</li>
 * <li>{@link LoginRateLimitingFilter} – rate-limits authentication
 * requests.</li>
 * <li>{@link JwtAuthorizationFilter} – validates JWT access tokens and
 * populates the {@code SecurityContext}.</li>
 * <li>{@link AuthNoCacheFilter} – disables client-side caching for
 * authenticated responses.</li>
 * </ol>
 *
 * <h2>CORS</h2>
 * <p>
 * Cross-Origin Resource Sharing (CORS) is configured via
 * {@link SecurityCorsProperties} and supports credentialed requests when
 * explicitly allowed by configuration.
 * </p>
 *
 * <h2>Password encoding</h2>
 * <p>
 * Passwords are encoded using a
 * {@link org.springframework.security.crypto.password.DelegatingPasswordEncoder},
 * allowing algorithm upgrades without invalidating existing hashes.
 * </p>
 *
 * <p>
 * This configuration is designed to be <b>production-ready</b> and
 * extensible for enterprise environments.
 * </p>
 */

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private static final String[] PUBLIC_ENDPOINTS = {
            "/actuator/health/**",
            "/actuator/info",
            "/v3/api-docs/**",
            "/swagger-ui/**",
    };

    private static final String[] AUTH_ENDPOINTS = {
            "/api/v1/auth/login",
            "/api/v1/auth/refresh"
    };

    private final JwtAuthorizationFilter jwtAuthz;
    private final CustomAuthEntryPoint entryPoint;
    private final CustomAccessDeniedHandler deniedHandler;
    private final LoginRateLimitingFilter loginRateLimitingFilter;
    private final SecurityHeadersFilter securityHeadersFilter;
    private final AuthNoCacheFilter authNoCacheFilter;
    private final CorrelationIdFilter correlationIdFilter;

    public SecurityConfig(
            JwtAuthorizationFilter jwtAuthz,
            CustomAuthEntryPoint entryPoint,
            CustomAccessDeniedHandler deniedHandler,
            LoginRateLimitingFilter loginRateLimitingFilter,
            SecurityHeadersFilter securityHeadersFilter,
            AuthNoCacheFilter authNoCacheFilter,
            CorrelationIdFilter correlationIdFilter) {
        this.jwtAuthz = jwtAuthz;
        this.entryPoint = entryPoint;
        this.deniedHandler = deniedHandler;
        this.loginRateLimitingFilter = loginRateLimitingFilter;
        this.securityHeadersFilter = securityHeadersFilter;
        this.authNoCacheFilter = authNoCacheFilter;
        this.correlationIdFilter = correlationIdFilter;
    }

    /**
     * Defines the main Spring Security filter chain.
     *
     * <p>
     * Configures stateless security, exception handling, authorization rules
     * and the explicit order of custom security filters.
     * </p>
     *
     * @param http the {@link HttpSecurity} builder
     * @return the configured {@link SecurityFilterChain}
     * @throws Exception if the security configuration cannot be built
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(deniedHandler))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                        .requestMatchers(HttpMethod.POST, AUTH_ENDPOINTS).permitAll()
                        .anyRequest().authenticated());

        // ---Filter order: explicit & documented--
        http.addFilterBefore(correlationIdFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterAfter(securityHeadersFilter, CorrelationIdFilter.class);

        // IMPORTANT:
        // LoginRateLimitingFilter MUST internally restrict itself to AUTH_ENDPOINTS.
        // This configuration assumes that behavior by contract.
        http.addFilterAfter(loginRateLimitingFilter, SecurityHeadersFilter.class);

        // --JWT auth
        http.addFilterAfter(jwtAuthz, LoginRateLimitingFilter.class);

        // Disable caching for authenticated responses
        http.addFilterAfter(authNoCacheFilter, JwtAuthorizationFilter.class);

        return http.build();
    }

    /**
     * Configures Cross-Origin Resource Sharing (CORS) for the application.
     *
     * <p>
     * Configuration values are provided via {@link SecurityCorsProperties}
     * and allow fine-grained control over origins, headers and credentials.
     * </p>
     *
     * @param props the CORS security properties
     * @return a {@link CorsConfigurationSource} instance
     */

    @Bean
    public CorsConfigurationSource corsConfigurationSource(SecurityCorsProperties props) {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOrigins(props.allowedOrigins());
        cfg.setAllowedMethods(props.allowedMethods());
        cfg.setAllowedHeaders(props.allowedHeaders());
        cfg.setExposedHeaders(props.exposedHeaders());
        cfg.setAllowCredentials(props.allowCredentials());
        cfg.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cfg);
        return source;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
