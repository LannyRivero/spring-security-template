package com.lanny.spring_security_template.infrastructure.security;

import com.lanny.spring_security_template.application.auth.port.out.JwtValidator;
import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;
import java.util.stream.Collectors;

@Component
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

    String path = request.getRequestURI();

    // 1️⃣ Excluir Swagger + Actuator
    if (path.startsWith("/actuator")
        || path.startsWith("/v3/api-docs")
        || path.startsWith("/swagger-ui")) {

      chain.doFilter(request, response);
      return;
    }

    // 2️⃣ Extraer Bearer
    String header = request.getHeader(HttpHeaders.AUTHORIZATION);

    if (!StringUtils.hasText(header) || !header.startsWith("Bearer ")) {
      chain.doFilter(request, response);
      return;
    }

    String token = header.substring(7);

    try {
      // 3️⃣ Validación estricta del JWT
      JwtClaimsDTO claims = jwtValidator.validate(token);

      // 4️⃣ Anti-replay
      if (tokenBlacklistGateway.isRevoked(claims.jti())) {
        throw new IllegalArgumentException("Token revoked");
      }

      // 5️⃣ Construir Authentication solo con roles válidos
      Set<SimpleGrantedAuthority> authorities = claims.roles()
          .stream()
          .map(SimpleGrantedAuthority::new)
          .collect(Collectors.toSet());

      var auth = new UsernamePasswordAuthenticationToken(
          claims.sub(),
          null,
          authorities);

      SecurityContextHolder.getContext().setAuthentication(auth);

    } catch (Exception e) {
      // No autenticado
      SecurityContextHolder.clearContext();
    }

    chain.doFilter(request, response);
  }
}
