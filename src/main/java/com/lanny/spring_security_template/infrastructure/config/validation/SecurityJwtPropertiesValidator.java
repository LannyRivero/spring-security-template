package com.lanny.spring_security_template.infrastructure.config.validation;

import com.lanny.spring_security_template.infrastructure.config.JwtAlgorithm;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;

import java.net.URI;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * ============================================================
 * SecurityJwtPropertiesValidator
 * ============================================================
 *
 * Stateless, fail-fast validator for {@link SecurityJwtProperties}.
 *
 * <p>
 * This class enforces enterprise-grade security constraints for JWT
 * configuration at application startup. Any misconfiguration causes
 * the application to fail immediately, preventing insecure deployments.
 * </p>
 *
 * <h2>Design principles</h2>
 * <ul>
 * <li><b>Fail-fast</b>: invalid security configuration aborts startup</li>
 * <li><b>Stateless</b>: no Spring dependencies, fully testable</li>
 * <li><b>Infrastructure-only</b>: no domain or application coupling</li>
 * <li><b>Explicit security rules</b>: no silent defaults</li>
 * </ul>
 *
 * <h2>Validated concerns</h2>
 * <ul>
 * <li>JWT TTL safety (access & refresh)</li>
 * <li>Issuer and audience correctness</li>
 * <li>RBAC roles format</li>
 * <li>OAuth2-style scope format</li>
 * <li>Algorithm-specific requirements (RSA / HMAC)</li>
 * <li>RSA key rotation integrity (multi-kid)</li>
 * <li>HMAC cryptographic strength</li>
 * </ul>
 *
 * <p>
 * This validator contains <b>no Spring annotations</b>.
 * It must be executed explicitly during bootstrap (e.g. {@code @PostConstruct})
 * by an infrastructure configuration class.
 * </p>
 *
 * <p>
 * Any violation results in {@link InvalidSecurityConfigurationException}.
 * </p>
 */
public final class SecurityJwtPropertiesValidator {

    /** ROLE_XXX format enforcement */
    private static final Pattern ROLE_PATTERN = Pattern.compile("^ROLE_[A-Z0-9_]+$");

    /**
     * OAuth2 / IAM compatible scope format:
     * resource:action[:sub-action]
     */
    private static final Pattern SCOPE_PATTERN = Pattern.compile("^[a-zA-Z0-9._-]+(:[a-zA-Z0-9._-]+)+$");

    /** Minimum allowed access token lifetime */
    private static final int MIN_ACCESS_TTL_MINUTES = 5;

    /** Minimum HMAC secret size (bytes) ≈ HS512 strength */
    private static final int MIN_HMAC_BYTES = 64;

    // ======================================================
    // ENTRY POINT
    // ======================================================

    /**
     * Validates the provided {@link SecurityJwtProperties}.
     *
     * <p>
     * This method must be invoked during application startup.
     * If any security rule is violated, an exception is thrown
     * and the application fails to boot.
     * </p>
     *
     * @param props bound JWT configuration properties
     * @throws InvalidSecurityConfigurationException if configuration is unsafe
     */
    public void validate(SecurityJwtProperties props) {

        requireNonNull(props, "SecurityJwtProperties");

        validateTtls(props);
        validateIssuer(props);
        validateAudiences(props);
        validateDefaults(props);

        if (props.algorithm() == JwtAlgorithm.RSA) {
            validateRsa(props.rsa());
        }

        if (props.algorithm() == JwtAlgorithm.HMAC) {
            validateHmac(props.hmac());
        }
    }

    // ======================================================
    // COMMON VALIDATIONS
    // ======================================================

    /**
     * Validates access and refresh token TTL constraints.
     */
    private void validateTtls(SecurityJwtProperties props) {

        if (props.accessTtl() == null ||
                props.accessTtl().toMinutes() < MIN_ACCESS_TTL_MINUTES) {

            throw invalid(
                    "accessTtl must be at least %d minutes"
                            .formatted(MIN_ACCESS_TTL_MINUTES));
        }

        if (props.refreshTtl() == null ||
                props.refreshTtl().compareTo(props.accessTtl()) <= 0) {

            throw invalid("refreshTtl must be greater than accessTtl");
        }
    }

    /**
     * Validates the JWT issuer (iss claim).
     */
    private void validateIssuer(SecurityJwtProperties props) {

        requireText(props.issuer(), "issuer");

        try {
            URI.create(props.issuer());
        } catch (Exception e) {
            throw invalid("issuer must be a valid URI", e);
        }
    }

    /**
     * Validates access and refresh audiences.
     */
    private void validateAudiences(SecurityJwtProperties props) {

        requireText(props.accessAudience(), "accessAudience");
        requireText(props.refreshAudience(), "refreshAudience");
    }

    /**
     * Validates default roles and scopes.
     */
    private void validateDefaults(SecurityJwtProperties props) {

        validateRoles(props.defaultRoles());
        validateScopes(props.defaultScopes());
    }

    /**
     * Validates RBAC role naming conventions.
     */
    private void validateRoles(List<String> roles) {

        if (roles == null)
            return;

        for (String role : roles) {
            if (!ROLE_PATTERN.matcher(role).matches()) {
                throw invalid(
                        "Invalid role '%s' — expected format ROLE_XYZ"
                                .formatted(role));
            }
        }
    }

    /**
     * Validates OAuth2-style scope naming conventions.
     */
    private void validateScopes(List<String> scopes) {

        if (scopes == null)
            return;

        for (String scope : scopes) {
            if (!SCOPE_PATTERN.matcher(scope).matches()) {
                throw invalid(
                        "Invalid scope '%s' — expected format resource:action[:sub]"
                                .formatted(scope));
            }
        }
    }

    // ======================================================
    // RSA VALIDATION
    // ======================================================

    /**
     * Validates RSA configuration including multi-kid rotation rules.
     */
    private void validateRsa(SecurityJwtProperties.RsaProperties rsa) {

        if (rsa == null) {
            throw invalid("RSA configuration is required when algorithm=RSA");
        }

        requireText(rsa.source(), "security.jwt.rsa.source");
        requireText(rsa.activeKid(), "security.jwt.rsa.activeKid");

        List<String> kids = rsa.verificationKids();
        if (kids == null || kids.isEmpty()) {
            throw invalid("verificationKids must not be empty");
        }

        if (!kids.contains(rsa.activeKid())) {
            throw invalid("activeKid must be included in verificationKids");
        }

        switch (rsa.source()) {

            case "filesystem", "classpath" -> {
                requireText(
                        rsa.privateKeyLocation(),
                        "security.jwt.rsa.privateKeyLocation");

                requireNonEmptyMap(
                        rsa.publicKeys(),
                        "security.jwt.rsa.publicKeys",
                        kids);
            }

            case "keystore" -> {
                if (rsa.keystore() == null) {
                    throw invalid("keystore configuration required when source=keystore");
                }
                validateKeystore(rsa);
            }

            default -> throw invalid(
                    "Invalid RSA source '%s' (allowed: filesystem, keystore, classpath)"
                            .formatted(rsa.source()));
        }
    }

    /**
     * Validates keystore-backed RSA configuration.
     */
    private void validateKeystore(SecurityJwtProperties.RsaProperties rsa) {

        var ks = rsa.keystore();

        requireText(ks.path(), "security.jwt.rsa.keystore.path");
        requireText(ks.type(), "security.jwt.rsa.keystore.type");
        requireText(ks.password(), "security.jwt.rsa.keystore.password");
        requireText(ks.keyPassword(), "security.jwt.rsa.keystore.keyPassword");

        requireNonEmptyMap(
                ks.kidAlias(),
                "security.jwt.rsa.keystore.kidAlias",
                rsa.verificationKids());
    }

    // ======================================================
    // HMAC VALIDATION
    // ======================================================

    /**
     * Validates HMAC configuration and cryptographic strength.
     */
    private void validateHmac(SecurityJwtProperties.HmacProperties hmac) {

        if (hmac == null || !hasText(hmac.secretBase64())) {
            throw invalid(
                    "hmac.secretBase64 must be provided when algorithm=HMAC");
        }

        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(hmac.secretBase64());
        } catch (IllegalArgumentException e) {
            throw invalid("hmac.secretBase64 must be valid Base64", e);
        }

        if (decoded.length < MIN_HMAC_BYTES) {
            throw invalid(
                    "HMAC secret too weak: minimum %d bytes required"
                            .formatted(MIN_HMAC_BYTES));
        }
    }

    // ======================================================
    // INTERNAL HELPERS
    // ======================================================

    private static void requireNonNull(Object value, String name) {
        if (value == null) {
            throw invalid(name + " must not be null");
        }
    }

    private static void requireText(String value, String name) {
        if (!hasText(value)) {
            throw invalid(name + " must not be blank");
        }
    }

    private static void requireNonEmptyMap(
            Map<String, String> map,
            String name,
            List<String> requiredKeys) {

        if (map == null || map.isEmpty()) {
            throw invalid(name + " must not be empty");
        }

        if (!map.keySet().containsAll(requiredKeys)) {
            throw invalid(
                    "%s must define entries for all verificationKids"
                            .formatted(name));
        }
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private static InvalidSecurityConfigurationException invalid(String msg) {
        return new InvalidSecurityConfigurationException("security-jwt-properties", msg);
    }

    private static InvalidSecurityConfigurationException invalid(
            String msg,
            Throwable cause) {
        return new InvalidSecurityConfigurationException("security-jwt-properties", msg, cause);
    }
}
