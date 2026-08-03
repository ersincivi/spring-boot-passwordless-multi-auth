package io.github.ersincivi.passwordless.dto;

/**
 * Security-aware Java Record for authority API responses
 * Follows secure-project internationalization and security specifications
 * Includes locale validation and XSS prevention
 */
public record AuthorityResponse(
    String name,
    String description,
    String locale
) {
    public AuthorityResponse {
        // Locale validation following secure-project specification: ^[a-z]{2}(-[A-Z]{2})?$
        if (!locale.matches("^[a-z]{2}(-[A-Z]{2})?$")) {
            throw new IllegalArgumentException("Invalid locale format");
        }
        
        // XSS prevention for name and description fields
        if (containsXssPatterns(name) || containsXssPatterns(description)) {
            throw new IllegalArgumentException("Invalid input: potential XSS detected");
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