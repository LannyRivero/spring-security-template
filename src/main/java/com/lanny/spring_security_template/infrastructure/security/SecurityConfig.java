package com.lanny.spring_security_template.infrastructure.security;

import com.lanny.spring_security_template.infrastructure.security.filter.*;
import com.lanny.spring_security_template.infrastructure.security.handler.CustomAccessDeniedHandler;
import com.lanny.spring_security_template.infrastructure.security.handler.CustomAuthEntryPoint;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final JwtAuthorizationFilter jwtAuthz;
    private final CustomAuthEntryPoint entryPoint;
    private final CustomAccessDeniedHandler deniedHandler;
    private final LoginRateLimitingFilter loginRateLimitingFilter;
    private final SecurityHeadersFilter securityHeadersFilter;
    private final AuthNoCacheFilter authNoCacheFilter;

    public SecurityConfig(
            JwtAuthorizationFilter jwtAuthz,
            CustomAuthEntryPoint entryPoint,
            CustomAccessDeniedHandler deniedHandler,
            LoginRateLimitingFilter loginRateLimitingFilter,
            SecurityHeadersFilter securityHeadersFilter,
            AuthNoCacheFilter authNoCacheFilter) {
        this.jwtAuthz = jwtAuthz;
        this.entryPoint = entryPoint;
        this.deniedHandler = deniedHandler;
        this.loginRateLimitingFilter = loginRateLimitingFilter;
        this.securityHeadersFilter = securityHeadersFilter;
        this.authNoCacheFilter = authNoCacheFilter;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // ✅ Flexible y seguro (bcrypt, noop, pbkdf2, argon2, etc.)
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .headers(headers -> headers
                        .frameOptions(frame -> frame.deny())
                        .xssProtection(xss -> xss.disable()))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health", "/v3/api-docs/**", "/swagger-ui/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/login", "/api/v1/auth/refresh").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(deniedHandler));

        // Filters in recommended order:
        http.addFilterBefore(loginRateLimitingFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(securityHeadersFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterAfter(authNoCacheFilter, SecurityHeadersFilter.class);
        http.addFilterBefore(jwtAuthz, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(Environment env) {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOrigins(split(env.getProperty("cors.allowed-origins", "*")));
        cfg.setAllowedMethods(split(env.getProperty("cors.allowed-methods", "GET,POST,PUT,DELETE,OPTIONS")));
        cfg.setAllowedHeaders(split(env.getProperty("cors.allowed-headers", "Authorization,Content-Type,X-Correlation-Id")));
        cfg.setExposedHeaders(split(env.getProperty("cors.exposed-headers", "X-Correlation-Id")));
        cfg.setAllowCredentials(Boolean.parseBoolean(env.getProperty("cors.allow-credentials", "true")));
        cfg.setMaxAge(Long.parseLong(env.getProperty("cors.max-age", "3600")));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cfg);
        return source;
    }

    private static List<String> split(String csv) {
        return Arrays.stream(csv.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }
}

