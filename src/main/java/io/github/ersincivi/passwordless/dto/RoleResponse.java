package io.github.ersincivi.passwordless.dto;

import io.github.ersincivi.passwordless.domain.Role;
import java.util.Set;

/**
 * Security-aware Java Record for role API responses
 * Follows secure-project internationalization and security specifications
 * Includes locale validation and XSS prevention
 */
public record RoleResponse(
    Role.Code code,
    String name,
    Set<String> authorities,
    String locale
) {
    public RoleResponse {
        // Locale validation following secure-project specification: ^[a-z]{2}(-[A-Z]{2})?$
        if (!locale.matches("^[a-z]{2}(-[A-Z]{2})?$")) {
            throw new IllegalArgumentException("Invalid locale format");
        }
        
        // XSS prevention for name field
        if (containsXssPatterns(name)) {
            throw new IllegalArgumentException("Invalid input: potential XSS detected in role name");
        }
    }
    
    /**
     * Basic XSS pattern detection
     * Protects against common script injection attempts
     */
    private static boolean containsXssPatterns(String input) {
        if (input == null) return false;
        String lower = input.toLowerCase();
        return lower.contains("<script") || 
               lower.contains("javascript:") || 
               lower.contains("onerror=") ||
               lower.contains("onload=") ||
               lower.contains("eval(");
    }
}