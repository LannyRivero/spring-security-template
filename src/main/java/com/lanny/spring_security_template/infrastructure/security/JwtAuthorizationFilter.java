package com.lanny.spring_security_template.infrastructure.security;

import com.lanny.spring_security_template.application.auth.port.out.JwtValidator;
import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.infrastructure.jwt.JwtAuthoritiesMapper;
import com.lanny.spring_security_template.infrastructure.security.jwt.JwtAuthFailureReason;
import com.lanny.spring_security_template.infrastructure.security.jwt.exception.InvalidTokenTypeException;
import com.lanny.spring_security_template.infrastructure.security.jwt.exception.NoAuthoritiesException;
import com.lanny.spring_security_template.infrastructure.security.jwt.exception.TokenRevokedException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static com.lanny.spring_security_template.infrastructure.observability.MdcKeys.*;

/**
 * {@code JwtAuthorizationFilter}
 *
 * <p>
 * Spring Security filter responsible for <b>JWT-based authorization</b>
 * using <b>access tokens only</b>.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Extract and validate Bearer tokens</li>
 * <li>Reject refresh tokens explicitly</li>
 * <li>Prevent token replay using blacklist checks</li>
 * <li>Map roles and scopes to granted authorities</li>
 * <li>Populate the {@link SecurityContextHolder}</li>
 * </ul>
 *
 * <h2>Observability</h2>
 * <ul>
 * <li>Uses MDC when available (correlationId, request path, username)</li>
 * <li>Falls back to request data if MDC is missing</li>
 * <li>Never logs tokens or PII</li>
 * </ul>
 *
 * <p>
 * Designed for stateless, production-grade APIs and compliant with
 * OWASP ASVS / ENS requirements.
 * </p>
 */
@Component
@Order(80)
public class JwtAuthorizationFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(JwtAuthorizationFilter.class);

  private final JwtValidator jwtValidator;
  private final TokenBlacklistGateway tokenBlacklistGateway;
  private final JwtAuthoritiesMapper authoritiesMapper;

  public JwtAuthorizationFilter(
      JwtValidator jwtValidator,
      TokenBlacklistGateway tokenBlacklistGateway,
      JwtAuthoritiesMapper authoritiesMapper) {
    this.jwtValidator = jwtValidator;
    this.tokenBlacklistGateway = tokenBlacklistGateway;
    this.authoritiesMapper = authoritiesMapper;
  }

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain chain)
      throws ServletException, IOException {

    String header = request.getHeader(HttpHeaders.AUTHORIZATION);

    if (!StringUtils.hasText(header) || !header.startsWith("Bearer ")) {
      chain.doFilter(request, response);
      return;
    }

    String token = header.substring(7);

    try {
      JwtClaimsDTO claims = jwtValidator.validate(token);

      if (!claims.isAccessToken()) {
        throw new InvalidTokenTypeException();
      }

      if (tokenBlacklistGateway.isRevoked(claims.jti())) {
        throw new TokenRevokedException();
      }

      var authorities = authoritiesMapper.map(claims);

      var authentication = new UsernamePasswordAuthenticationToken(
          claims.sub(),
          null,
          authorities);

      SecurityContextHolder.getContext()
          .setAuthentication(authentication);

      MDC.put(USERNAME, claims.sub());

    } catch (Exception ex) {

      JwtAuthFailureReason reason = mapFailureReason(ex);

      String path = MDC.get(REQUEST_PATH) != null
          ? MDC.get(REQUEST_PATH)
          : request.getRequestURI();

      String method = request.getMethod();
      String correlationId = MDC.get(CORRELATION_ID);

      log.warn(
          "JWT authorization failed reason={} method={} path={} correlationId={}",
          reason,
          method,
          path,
          correlationId);

      SecurityContextHolder.clearContext();
    }

    try {
      chain.doFilter(request, response);
    } finally {
      MDC.remove(USERNAME);
    }
  }

  private JwtAuthFailureReason mapFailureReason(Exception ex) {

    if (ex instanceof TokenRevokedException) {
      return JwtAuthFailureReason.TOKEN_REVOKED;
    }
    if (ex instanceof InvalidTokenTypeException) {
      return JwtAuthFailureReason.INVALID_TYPE;
    }
    if (ex instanceof NoAuthoritiesException) {
      return JwtAuthFailureReason.NO_AUTHORITIES;
    }
    if (ex instanceof IllegalArgumentException) {
      return JwtAuthFailureReason.INVALID_CLAIMS;
    }
    return JwtAuthFailureReason.UNKNOWN;
  }
}
