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
 * <p>
 * This filter:
 * </p>
 * <ul>
 * <li>Extracts and validates JWT access tokens from the
 * {@code Authorization: Bearer <token>} header</li>
 * <li>Rejects refresh tokens explicitly</li>
 * <li>Prevents token replay via blacklist checks</li>
 * <li>Maps roles and scopes to Spring Security authorities</li>
 * <li>Populates the {@link SecurityContextHolder} for authorized requests</li>
 * </ul>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>Only cryptographically valid access tokens are accepted</li>
 * <li>Refresh tokens can never be used for authorization</li>
 * <li>Revoked tokens are rejected before authentication</li>
 * <li>Tokens without granted authorities are rejected</li>
 * </ul>
 *
 * <h2>Observability</h2>
 * <ul>
 * <li>Authenticated username is propagated via MDC</li>
 * <li>Security logs contain only controlled failure reasons</li>
 * <li>No sensitive data (tokens, secrets) is logged</li>
 * </ul>
 *
 * <p>
 * This filter is designed for <b>stateless, production-grade APIs</b>
 * and complies with enterprise security standards (OWASP ASVS, ENS).
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

  /**
   * Performs JWT authorization for an incoming HTTP request.
   *
   * <p>
   * Processing steps:
   * </p>
   * <ol>
   * <li>Skip public and system endpoints</li>
   * <li>Extract Bearer token from Authorization header</li>
   * <li>Validate token cryptographically and semantically</li>
   * <li>Reject revoked or non-access tokens</li>
   * <li>Map roles and scopes to granted authorities</li>
   * <li>Populate the security context</li>
   * </ol>
   *
   * <p>
   * If validation fails, the request continues without authentication
   * and a controlled security event is logged.
   * </p>
   *
   * @param request  incoming HTTP request
   * @param response HTTP response
   * @param chain    filter chain
   *
   * @throws ServletException in case of servlet errors
   * @throws IOException      in case of I/O errors
   */
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

      log.warn(
          "JWT authorization failed reason={} path={} correlationId={}",
          reason,
          MDC.get(REQUEST_PATH),
          MDC.get(CORRELATION_ID));

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