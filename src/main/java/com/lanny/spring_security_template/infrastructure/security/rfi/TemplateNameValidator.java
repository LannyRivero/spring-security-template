package com.lanny.spring_security_template.infrastructure.security.rfi;

import java.util.Set;

public class TemplateNameValidator {

    private final Set<String> allowedTemplates = Set.of(
            "INVOICE_BASIC",
            "INVOICE_PRO",
            "REPORT_SUMMARY"
    );

    public String validate(String templateName) {
        if (templateName == null || templateName.isBlank()) {
            throw new IllegalArgumentException("Template name is required");
        }

        if (templateName.contains("://") || templateName.contains("..") || templateName.startsWith("/")) {
            throw new IllegalArgumentException("Invalid template name");
        }

        if (!allowedTemplates.contains(templateName)) {
            throw new IllegalArgumentException("Unknown template: " + templateName);
        }

        return templateName;
    }
}
