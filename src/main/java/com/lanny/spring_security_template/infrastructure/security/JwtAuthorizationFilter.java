package com.lanny.spring_security_template.infrastructure.security;

import com.lanny.spring_security_template.infrastructure.jwt.JwtClaimsExtractor;
import com.lanny.spring_security_template.infrastructure.jwt.JwtUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Stream;

@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(JwtAuthorizationFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";
    private static final int BEARER_PREFIX_LENGTH = 7;

    private final JwtUtils jwtUtils;
    private final JwtClaimsExtractor extractor;

    public JwtAuthorizationFilter(JwtUtils jwtUtils, JwtClaimsExtractor extractor) {
        this.jwtUtils = jwtUtils;
        this.extractor = extractor;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest req, @NonNull HttpServletResponse res,
            @NonNull FilterChain chain)
            throws ServletException, IOException {

        String header = req.getHeader(HttpHeaders.AUTHORIZATION);

        if (header != null && header.startsWith(BEARER_PREFIX)) {
            String token = header.substring(BEARER_PREFIX_LENGTH);
            try {
                JWTClaimsSet claims = jwtUtils.validateAndParse(token);
                String username = claims.getSubject();
                List<String> roles = extractor.extractRoles(claims);
                List<String> scopes = extractor.extractScopes(claims);

                var authorities = Stream.concat(
                        roles.stream().map(r -> new SimpleGrantedAuthority("ROLE_" + r)),
                        scopes.stream().map(s -> new SimpleGrantedAuthority("SCOPE_" + s))).toList();

                var authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (Exception e) {
                logger.warn("JWT validation failed: {}", e.getMessage());
                // Let the EntryPoint handle the 401
                SecurityContextHolder.clearContext();
            }
        }
        chain.doFilter(req, res);
    }
}
