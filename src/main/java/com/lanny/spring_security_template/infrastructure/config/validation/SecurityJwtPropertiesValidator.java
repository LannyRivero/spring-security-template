package com.lanny.spring_security_template.infrastructure.config.validation;

import com.lanny.spring_security_template.infrastructure.config.JwtAlgorithm;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.util.regex.Pattern;

@Component
public class SecurityJwtPropertiesValidator {

    private static final Pattern ROLE_PATTERN = Pattern.compile("^ROLE_[A-Z0-9_]+$");

    // OAuth2 / Google IAM / AWS IAM compatible
    private static final Pattern SCOPE_PATTERN = Pattern.compile("^[a-zA-Z0-9._-]+(:[a-zA-Z0-9._-]+)+$");

    private final SecurityJwtProperties props;

    public SecurityJwtPropertiesValidator(SecurityJwtProperties props) {
        this.props = props;
    }

    @PostConstruct
    public void validate() {

        // ---------------- TTLs ----------------
        if (props.accessTtl() == null || props.accessTtl().toMinutes() < 5) {
            throw new InvalidSecurityConfigurationException("accessTtl must be at least 5 minutes");
        }

        if (props.refreshTtl().compareTo(props.accessTtl()) <= 0) {
            throw new InvalidSecurityConfigurationException("refreshTtl must be greater than accessTtl");
        }

        // ---------------- Issuer ----------------
        if (!StringUtils.hasText(props.issuer())) {
            throw new InvalidSecurityConfigurationException("issuer cannot be blank.");
        }

        try {
            URI.create(props.issuer());
        } catch (Exception e) {
            throw new InvalidSecurityConfigurationException("issuer must be a valid URI.", e);
        }

        // ---------------- Audience ----------------
        if (!StringUtils.hasText(props.accessAudience())) {
            throw new InvalidSecurityConfigurationException("accessAudience cannot be blank.");
        }

        if (!StringUtils.hasText(props.refreshAudience())) {
            throw new InvalidSecurityConfigurationException("refreshAudience cannot be blank.");
        }

        // ---------------- Roles ----------------
        if (props.defaultRoles() != null) {
            for (String role : props.defaultRoles()) {
                if (!ROLE_PATTERN.matcher(role).matches()) {
                    throw new InvalidSecurityConfigurationException(
                            "Invalid role: %s — expected format ROLE_XYZ".formatted(role));
                }
            }
        }

        // ---------------- Scopes ----------------
        if (props.defaultScopes() != null) {
            for (String scope : props.defaultScopes()) {
                if (!SCOPE_PATTERN.matcher(scope).matches()) {
                    throw new InvalidSecurityConfigurationException(
                            "Invalid scope: %s — expected format xxx:yyy or xxx:yyy:zzz".formatted(scope));
                }
            }
        }

        // ---------------- Algorithm-specific ----------------
        if (props.algorithm() == JwtAlgorithm.HMAC) {
            if (props.hmac() == null || !StringUtils.hasText(props.hmac().secretBase64())) {
                throw new InvalidSecurityConfigurationException(
                        "JWT algorithm is HMAC but hmac.secret-base64 is missing or blank");
            }
        }

    }
}
