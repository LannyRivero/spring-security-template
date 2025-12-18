package com.lanny.spring_security_template.infrastructure.security;

import com.lanny.spring_security_template.application.auth.port.out.JwtValidator;
import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
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
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

/**
 * Spring Security filter responsible for JWT-based authorization.
 *
 * <p>
 * This filter validates <b>JWT access tokens</b> provided via the
 * {@code Authorization: Bearer <token>} header and populates the
 * {@link org.springframework.security.core.context.SecurityContext}
 * when authorization is successful.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Extract and validate JWT tokens using {@link JwtValidator}.</li>
 * <li>Reject refresh tokens explicitly (only access tokens are allowed).</li>
 * <li>Check token revocation status via {@link TokenBlacklistGateway}
 * (anti-replay protection).</li>
 * <li>Map roles and scopes to Spring Security authorities
 * ({@code ROLE_*} and {@code SCOPE_*}).</li>
 * <li>Populate the
 * {@link org.springframework.security.core.context.SecurityContext}
 * with an authenticated principal.</li>
 * </ul>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>Refresh tokens can <b>never</b> be used to access protected
 * resources.</li>
 * <li>Tokens without any granted authorities are rejected.</li>
 * <li>Revoked tokens are rejected before authentication.</li>
 * </ul>
 *
 * <h2>Observability</h2>
 * <p>
 * The authenticated username is added to the logging
 * {@link org.slf4j.MDC} for request tracing and audit purposes.
 * No sensitive data (such as tokens) is logged.
 * </p>
 *
 * <h2>Excluded endpoints</h2>
 * <p>
 * This filter is bypassed for public system endpoints such as:
 * </p>
 * <ul>
 * <li>{@code /actuator/**}</li>
 * <li>{@code /v3/api-docs/**}</li>
 * <li>{@code /swagger-ui/**}</li>
 * </ul>
 *
 * <p>
 * This filter is designed for <b>stateless, production-grade APIs</b>
 * and follows enterprise security best practices.
 * </p>
 */

@Component
@Order(80)
public class JwtAuthorizationFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(JwtAuthorizationFilter.class);

  private final JwtValidator jwtValidator;
  private final TokenBlacklistGateway tokenBlacklistGateway;

  public JwtAuthorizationFilter(
      JwtValidator jwtValidator,
      TokenBlacklistGateway tokenBlacklistGateway) {
    this.jwtValidator = jwtValidator;
    this.tokenBlacklistGateway = tokenBlacklistGateway;
  }

  /**
   * Performs JWT authorization for incoming HTTP requests.
   *
   * <p>
   * If a valid JWT access token is present, the security context is populated
   * with an authenticated principal. Otherwise, the request continues without
   * authentication.
   * </p>
   *
   * @param request  the incoming HTTP request
   * @param response the HTTP response
   * @param chain    the filter chain
   * @throws ServletException in case of servlet errors
   * @throws IOException      in case of I/O errors
   */
  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain chain) throws ServletException, IOException {

    String path = request.getRequestURI();

    if (path.startsWith("/actuator")
        || path.startsWith("/v3/api-docs")
        || path.startsWith("/swagger-ui")) {
      chain.doFilter(request, response);
      return;
    }

    String header = request.getHeader(HttpHeaders.AUTHORIZATION);

    if (!StringUtils.hasText(header) || !header.startsWith("Bearer ")) {
      chain.doFilter(request, response);
      return;
    }

    String token = header.substring(7);

    try {
      JwtClaimsDTO claims = jwtValidator.validate(token);

      if (!claims.isAccessToken()) {
        throw new BadCredentialsException("Refresh tokens cannot be used for authorization");
      }

      if (tokenBlacklistGateway.isRevoked(claims.jti())) {
        throw new BadCredentialsException("Token has been revoked");
      }

      Set<SimpleGrantedAuthority> authorities = new HashSet<>();

      claims.roles().forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));

      claims.scopes().forEach(scope -> authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope)));

      if (authorities.isEmpty()) {
        throw new BadCredentialsException("Token does not grant any authority");
      }

      var authentication = new UsernamePasswordAuthenticationToken(
          claims.sub(),
          null,
          authorities);

      SecurityContextHolder.getContext().setAuthentication(authentication);

      MDC.put("username", claims.sub());

    } catch (BadCredentialsException ex) {
      log.debug("JWT authorization failed: {}", ex.getMessage());
      SecurityContextHolder.clearContext();
    } catch (Exception ex) {
      log.warn("Unexpected JWT authorization error", ex);
      SecurityContextHolder.clearContext();
    }

    try {
      chain.doFilter(request, response);
    } finally {
      MDC.remove("username");
    }
  }
}
