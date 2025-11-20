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

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

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
                        .requestMatchers("/v3/api-docs/**", "/actuator/**", "/swagger-ui/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/login", "/api/v1/auth/refresh").permitAll()
                        .anyRequest().authenticated());

        http.addFilterBefore(correlationIdFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(securityHeadersFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(loginRateLimitingFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(jwtAuthz, UsernamePasswordAuthenticationFilter.class);
        http.addFilterAfter(authNoCacheFilter, JwtAuthorizationFilter.class);

        return http.build();
    }

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
}
