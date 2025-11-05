package com.lanny.spring_security_template.infrastructure.security;

import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;

@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {
  private final TokenProvider tokenProvider; 
  private final GrantedAuthoritiesMapper authoritiesMapper;

  @Override
  protected void doFilterInternal(@NonNull HttpServletRequest req, @NonNull HttpServletResponse res, @NonNull FilterChain chain)
      throws ServletException, IOException {

    String header = req.getHeader(HttpHeaders.AUTHORIZATION);
    if (header != null && header.startsWith("Bearer ")) {
      String token = header.substring(7);

      tokenProvider.parseClaims(token).ifPresent(claims -> {
        var auths = new ArrayList<GrantedAuthority>();
        claims.roles().forEach(r -> auths.add(new SimpleGrantedAuthority("ROLE_" + r)));
        claims.scopes().forEach(s -> auths.add(new SimpleGrantedAuthority("SCOPE_" + s)));

        var authentication = new UsernamePasswordAuthenticationToken(
            claims.sub(), null, authoritiesMapper.mapAuthorities(auths));

        SecurityContextHolder.getContext().setAuthentication(authentication);
      });
    }
    chain.doFilter(req, res);
  }
}