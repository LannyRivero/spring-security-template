package com.lanny.spring_security_template.infrastructure.security;

import com.lanny.spring_security_template.infrastructure.jwt.JwtClaimsExtractor;
import com.lanny.spring_security_template.infrastructure.jwt.nimbus.JwtUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

/**
 * 🔐 JwtAuthorizationFilter
 *
 * Filtro encargado de:
 *  - Extraer el token JWT del encabezado Authorization.
 *  - Validar y parsear el token con JwtUtils.
 *  - Construir las autoridades (roles + scopes) esperadas por Spring Security.
 *  - Poblar el SecurityContext con la autenticación válida.
 */
@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthorizationFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";
    private static final int BEARER_PREFIX_LENGTH = 7;

    private final JwtUtils jwtUtils;
    private final JwtClaimsExtractor extractor;

    public JwtAuthorizationFilter(JwtUtils jwtUtils, JwtClaimsExtractor extractor) {
        this.jwtUtils = jwtUtils;
        this.extractor = extractor;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain chain
    ) throws ServletException, IOException {

        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        // No token → continuar la cadena sin autenticación
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        String token = header.substring(BEARER_PREFIX_LENGTH);
        try {
            // 1️⃣ Validar y obtener claims
            JWTClaimsSet claims = jwtUtils.validateAndParse(token);
            String username = claims.getSubject();

            // 2️⃣ Extraer roles y scopes normalizados
            List<String> roles = extractor.extractRoles(claims);
            List<String> scopes = extractor.extractScopes(claims);

            // 3️⃣ Unir roles y scopes en un solo conjunto de autoridades
            var authorities = Stream.concat(
                    roles.stream()
                            .map(SimpleGrantedAuthority::new),
                    scopes.stream()
                            .map(SimpleGrantedAuthority::new)
            ).toList();

            // 4️⃣ Construir el objeto de autenticación
            var authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            logger.debug("✅ JWT authenticated user '{}' with authorities: {}", username, authorities);

        } catch (Exception e) {
            logger.warn("❌ JWT validation failed: {}", e.getMessage());
            SecurityContextHolder.clearContext();
            // Dejar que el AuthenticationEntryPoint maneje el 401
        }

        chain.doFilter(request, response);
    }
}

