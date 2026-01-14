package com.lanny.spring_security_template.infrastructure.security;

import static com.lanny.spring_security_template.infrastructure.observability.MdcKeys.*;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.lanny.spring_security_template.application.auth.port.out.JwtValidator;
import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.infrastructure.jwt.JwtAuthoritiesMapper;
import com.lanny.spring_security_template.infrastructure.jwt.exception.JwtValidationException;
import com.lanny.spring_security_template.infrastructure.security.jwt.JwtAuthFailureReason;
import com.lanny.spring_security_template.infrastructure.security.jwt.exception.InvalidTokenTypeException;
import com.lanny.spring_security_template.infrastructure.security.jwt.exception.JwtAuthenticationException;
import com.lanny.spring_security_template.infrastructure.security.jwt.exception.NoAuthoritiesException;
import com.lanny.spring_security_template.infrastructure.security.jwt.exception.TokenRevokedException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * {@code JwtAuthorizationFilter}
 *
 * <p>
 * Enterprise-grade JWT authorization filter responsible for validating
 * <b>ACCESS tokens only</b> and populating the Spring Security context.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Extract and validate Bearer access tokens</li>
 * <li>Reject refresh tokens explicitly</li>
 * <li>Prevent replay using token blacklist</li>
 * <li>Map roles and scopes to granted authorities</li>
 * <li>Populate {@link SecurityContextHolder}</li>
 * </ul>
 *
 * <h2>Failure semantics</h2>
 * <ul>
 * <li>All JWT validation failures are translated to
 * {@link JwtAuthenticationException}</li>
 * <li>Never returns HTTP responses directly</li>
 * <li>Delegates error handling to Spring Security entry points</li>
 * <li>JWT errors must NEVER result in HTTP 500</li>
 * </ul>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>No partial authentication is ever left in the context</li>
 * <li>No tokens or claims are logged</li>
 * <li>PII-safe structured logging</li>
 * </ul>
 */
@Component
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

    }
    // --------------------------------------------------
    // JWT validation errors → AUTHENTICATION FAILURE (401)
    // --------------------------------------------------
    catch (JwtValidationException ex) {
      SecurityContextHolder.clearContext();
      throw new JwtAuthenticationException("Invalid JWT token", ex);
    }
    // --------------------------------------------------
    // Authorization-level failures → ACCESS DENIED / 401
    // --------------------------------------------------
    catch (
        InvalidTokenTypeException | TokenRevokedException | NoAuthoritiesException | IllegalArgumentException ex) {

      JwtAuthFailureReason reason = mapFailureReason(ex);

      log.warn(
          "JWT authorization failed reason={} method={} path={} correlationId={}",
          reason,
          request.getMethod(),
          resolvePath(request),
          MDC.get(CORRELATION_ID));

      SecurityContextHolder.clearContext();
    }

    try {
      chain.doFilter(request, response);
    } finally {
      MDC.remove(USERNAME);
    }
  }

  // ======================================================
  // Helpers
  // ======================================================

  private String resolvePath(HttpServletRequest request) {
    String mdcPath = MDC.get(REQUEST_PATH);
    return (mdcPath != null && !mdcPath.isBlank())
        ? mdcPath
        : request.getRequestURI();
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
