package com.lanny.spring_security_template.infrastructure.security;

import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

  private final TokenProvider tokenProvider;
  private final GrantedAuthoritiesMapper authoritiesMapper;

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest req,
      @NonNull HttpServletResponse res,
      @NonNull FilterChain chain) throws ServletException, IOException {

    try {
      String header = req.getHeader(HttpHeaders.AUTHORIZATION);
      if (header != null && header.startsWith("Bearer ")) {
        String token = header.substring(7);

        if (tokenProvider.validateToken(token)) {
          tokenProvider.parseClaims(token).ifPresent(claims -> {
            var authorities = new ArrayList<GrantedAuthority>();
            claims.roles().forEach(r -> authorities.add(new SimpleGrantedAuthority("ROLE_" + r)));
            claims.scopes().forEach(s -> authorities.add(new SimpleGrantedAuthority("SCOPE_" + s)));

            var authentication = new UsernamePasswordAuthenticationToken(
                claims.sub(), null, authoritiesMapper.mapAuthorities(authorities));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.debug("✅ Authenticated '{}' (roles={}, scopes={})", claims.sub(), claims.roles(), claims.scopes());
          });
        } else {
          log.warn("❌ Invalid JWT from {}", req.getRemoteAddr());
        }
      }

      chain.doFilter(req, res);
    } finally {

    }
  }
}
