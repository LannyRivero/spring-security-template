package com.lanny.spring_security_template.infrastructure.security;

import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.infrastructure.security.filter.FilterOrder;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Order(FilterOrder.JWT_AUTHORIZATION)
@Component
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

  private final TokenProvider tokenProvider;
  private final GrantedAuthoritiesMapper authoritiesMapper;

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain chain) throws ServletException, IOException {

    try {
      String token = resolveToken(request);
      if (token == null) {
        chain.doFilter(request, response);
        return;
      }

      // Validar y parsear claims
      if (tokenProvider.validateToken(token)) {
        tokenProvider.parseClaims(token).ifPresent(claims -> {
          var authentication = buildAuthentication(claims, request);
          SecurityContextHolder.getContext().setAuthentication(authentication);

          // Añadir usuario al MDC para trazabilidad
          MDC.put("user", claims.sub());
          log.debug("✅ Authenticated '{}' (roles={}, scopes={})",
              claims.sub(), claims.roles(), claims.scopes());
        });
      } else {
        log.warn("❌ Invalid JWT from {}", request.getRemoteAddr());
      }

      chain.doFilter(request, response);

    } finally {
      // Limpiar contexto de seguridad y MDC después de cada request
      MDC.clear();
    }
  }

  /**
   * Extrae el token Bearer del encabezado Authorization.
   */
  private String resolveToken(HttpServletRequest req) {
    String header = req.getHeader(HttpHeaders.AUTHORIZATION);
    if (header != null && header.startsWith("Bearer ")) {
      return header.substring(7);
    }
    return null;
  }

  /**
   * Construye el objeto Authentication a partir de los claims.
   */
  private UsernamePasswordAuthenticationToken buildAuthentication(
      TokenProvider.TokenClaims claims, HttpServletRequest req) {

    List<GrantedAuthority> authorities = new ArrayList<>();
    claims.roles().forEach(r -> authorities.add(new SimpleGrantedAuthority("ROLE_" + r)));
    claims.scopes().forEach(s -> authorities.add(new SimpleGrantedAuthority("SCOPE_" + s)));

    var mappedAuthorities = authoritiesMapper.mapAuthorities(authorities);

    var authentication = new UsernamePasswordAuthenticationToken(
        claims.sub(), null, mappedAuthorities);
    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));

    return authentication;
  }
}
