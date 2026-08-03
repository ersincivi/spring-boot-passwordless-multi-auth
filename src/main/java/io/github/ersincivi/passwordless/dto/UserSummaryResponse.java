package io.github.ersincivi.passwordless.dto;

import java.time.Instant;
import java.util.Objects;

/**
 * Lightweight record for user summaries and listings
 * Optimized for dashboard views and administrative operations
 */
public record UserSummaryResponse(
    String username,
    String email,
    boolean enabled,
    boolean locked,
    Instant createdAt,
    Instant lastLoginAt,
    String locale
) {
    
    public UserSummaryResponse {
        Objects.requireNonNull(username, "username is required");
        Objects.requireNonNull(email, "email is required");
        Objects.requireNonNull(locale, "locale is required");
        
        // Locale validation following secure-project specification
        if (!locale.matches("^[a-z]{2}(-[A-Z]{2})?$")) {
            throw new IllegalArgumentException("Invalid locale format");
        }
        
        // XSS prevention
        if (containsXssPatterns(username) || containsXssPatterns(email)) {
            throw new IllegalArgumentException("Invalid input: potential XSS detected");
        }
    }
    
    private static boolean containsXssPatterns(String input) {
        if (input == null) return false;
        String lowerInput = input.toLowerCase();
        return lowerInput.contains("<script") || 
               lowerInput.contains("javascript:") || 
               lowerInput.contains("<") || 
               lowerInput.contains(">");
    }
}