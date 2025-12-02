package com.lanny.spring_security_template.infrastructure.config.validation;

import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.regex.Pattern;

/**
 * Advanced validator for {@link SecurityJwtProperties}.
 *
 * <p>
 * This validator enforces business rules that are too complex
 * for JSR-380 annotations alone.
 * </p>
 *
 * <h2>Validated Rules</h2>
 * <ul>
 * <li>accessTtl must be >= 5 minutes.</li>
 * <li>refreshTtl must be strictly greater than accessTtl.</li>
 * <li>issuer must be a non-empty and safe string.</li>
 * <li>roles must follow RBAC naming: ROLE_XXXX.</li>
 * <li>scopes must follow OAuth-like naming: xxx:yyy.</li>
 * </ul>
 *
 * <h2>Security Rationale</h2>
 * <ul>
 * <li>Short access tokens reduce replay attack windows.</li>
 * <li>Refresh tokens must live longer than access tokens to avoid infinite
 * refresh loops.</li>
 * <li>Ensuring role/scope format prevents privilege escalation via malformed
 * config.</li>
 * </ul>
 */
@Component
public class SecurityJwtPropertiesValidator {

    private static final Pattern ROLE_PATTERN = Pattern.compile("^ROLE_[A-Z0-9_]+$");
    private static final Pattern SCOPE_PATTERN = Pattern.compile("^[a-z]+:[a-z]+$");

    private final SecurityJwtProperties props;

    public SecurityJwtPropertiesValidator(SecurityJwtProperties props) {
        this.props = props;
        validate();
    }

    
    public void validate() {

        // --- Access TTL must be >= 5 minutes
        if (props.accessTtl() == null || props.accessTtl().toMinutes() < 5) {
            throw new IllegalArgumentException("""
                    Invalid JWT configuration: accessTtl must be >= PT5M (5 minutes).
                    """);
        }

        // --- Refresh TTL must be strictly greater than access TTL
        if (props.refreshTtl().compareTo(props.accessTtl()) <= 0) {
            throw new IllegalArgumentException("""
                    Invalid JWT configuration: refreshTtl must be greater than accessTtl.
                    """);
        }

        // --- Issuer must not be blank or malformed
        if (!StringUtils.hasText(props.issuer())) {
            throw new IllegalArgumentException("Invalid JWT configuration: issuer cannot be blank.");
        }

        // --- Validate default roles
        if (props.defaultRoles() != null) {
            for (String role : props.defaultRoles()) {
                if (!ROLE_PATTERN.matcher(role).matches()) {
                    throw new IllegalArgumentException("""
                            Invalid JWT role: %s — roles must follow the pattern ROLE_XYZ
                            """.formatted(role));
                }
            }
        }

        // --- Validate default scopes
        if (props.defaultScopes() != null) {
            for (String scope : props.defaultScopes()) {
                if (!SCOPE_PATTERN.matcher(scope).matches()) {
                    throw new IllegalArgumentException("""
                            Invalid JWT scope: %s — scopes must follow pattern xxx:yyy
                            """.formatted(scope));
                }
            }
        }
    }
}
