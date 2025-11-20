package com.lanny.spring_security_template.infrastructure.security;

import com.lanny.spring_security_template.application.auth.port.out.JwtValidator;
import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.stream.Collectors;

@Component
@Order(80) // después de CorrelationId y SecurityHeaders
public class JwtAuthorizationFilter extends OncePerRequestFilter {

  private final JwtValidator jwtValidator;
  private final TokenBlacklistGateway tokenBlacklistGateway;

  public JwtAuthorizationFilter(
      JwtValidator jwtValidator,
      TokenBlacklistGateway tokenBlacklistGateway) {
    this.jwtValidator = jwtValidator;
    this.tokenBlacklistGateway = tokenBlacklistGateway;
  }

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain chain) throws ServletException, IOException {

    try {

      // Excluir Swagger y Actuator
      String path = request.getRequestURI();
      if (path.startsWith("/actuator") ||
          path.startsWith("/v3/api-docs") ||
          path.startsWith("/swagger-ui")) {
        chain.doFilter(request, response);
        return;
      }

      String header = request.getHeader(HttpHeaders.AUTHORIZATION);

      if (!StringUtils.hasText(header) || !header.startsWith("Bearer ")) {
        chain.doFilter(request, response);
        return;
      }

      String token = header.substring(7);

      // 1️⃣ VALIDACIÓN ESTRICTA
      JwtClaimsDTO claims = jwtValidator.validate(token);

      // 2️⃣ Blacklist (anti-replay)
      if (tokenBlacklistGateway.isRevoked(claims.jti())) {
        throw new IllegalArgumentException("Token revoked");
      }

      // 3️⃣ Construcción de authorities
      var authorities = claims.roles()
          .stream()
          .map(SimpleGrantedAuthority::new)
          .collect(Collectors.toSet());

      // 4️⃣ Crear Authentication
      var auth = new UsernamePasswordAuthenticationToken(
          claims.sub(),
          null,
          authorities);

      SecurityContextHolder.getContext().setAuthentication(auth);

      // PASO 2: Añadir el usuario al MDC
      MDC.put("user", claims.sub());

    } catch (Exception ex) {
      SecurityContextHolder.clearContext();
    }

    try {
      chain.doFilter(request, response);
    } finally {
      // Limpiar MDC
      MDC.remove("user");
    }
  }
}
