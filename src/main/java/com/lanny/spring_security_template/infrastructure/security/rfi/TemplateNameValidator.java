package com.lanny.spring_security_template.infrastructure.security.rfi;

import java.util.Set;

/**
 * ============================================================
 * TemplateNameValidator
 * ============================================================
 *
 * <p>
 * Validates logical template identifiers to prevent Remote File Inclusion
 * (RFI),
 * path traversal and template injection attacks.
 * </p>
 *
 * <h2>Threat model</h2>
 * <p>
 * This validator ensures that only a predefined, trusted set of template
 * identifiers can be used by the application. It prevents attackers from:
 * </p>
 * <ul>
 * <li>Loading remote templates via URLs</li>
 * <li>Accessing filesystem paths</li>
 * <li>Injecting unexpected or malicious template names</li>
 * </ul>
 *
 * <h2>Validation strategy</h2>
 * <ul>
 * <li>Strict allowlist of known template identifiers</li>
 * <li>No dynamic resolution</li>
 * <li>No path or extension support</li>
 * </ul>
 *
 * <p>
 * This component validates identifiers only. It does not perform template
 * loading or rendering.
 * </p>
 */
public final class TemplateNameValidator {

    private static final Set<String> ALLOWED_TEMPLATES = Set.of(
            "INVOICE_BASIC",
            "INVOICE_PRO",
            "REPORT_SUMMARY");

    /**
     * Validates a logical template identifier.
     *
     * @param templateName raw template identifier
     * @return normalized, validated template identifier
     *
     * @throws IllegalArgumentException if the template identifier is invalid or not
     *                                  allowed
     */
    public String validate(String templateName) {

        if (templateName == null) {
            throw new IllegalArgumentException("Template identifier is required");
        }

        String normalized = templateName.trim();

        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("Template identifier is required");
        }

        // Reject obvious injection and path traversal attempts
        if (normalized.contains("://")
                || normalized.contains("..")
                || normalized.startsWith("/")) {

            throw new IllegalArgumentException("Invalid template identifier");
        }

        if (!ALLOWED_TEMPLATES.contains(normalized)) {
            throw new IllegalArgumentException("Template identifier not allowed");
        }

        return normalized;
    }
}
