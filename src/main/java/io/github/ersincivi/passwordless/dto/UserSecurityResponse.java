package io.github.ersincivi.passwordless.dto;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;

/**
 * Security-sensitive record for administrative user management
 * Includes MFA settings and role information with locale support
 */
public record UserSecurityResponse(
    String username,
    String email,
    boolean enabled,
    boolean locked,
    boolean mfaEnabled,
    String phoneNumber,
    String oauthProvider,
    Instant lastLoginAt,
    String lastLoginIp,
    Set<String> roles,
    String locale
) {
    
    public UserSecurityResponse {
        Objects.requireNonNull(username, "username is required");
        Objects.requireNonNull(email, "email is required");
        Objects.requireNonNull(roles, "roles is required");
        Objects.requireNonNull(locale, "locale is required");
        
        // Locale validation following secure-project specification
        if (!locale.matches("^[a-z]{2}(-[A-Z]{2})?$")) {
            throw new IllegalArgumentException("Invalid locale format");
        }
        
        // Input sanitization for security
        if (containsXssPatterns(username) || containsXssPatterns(email) || 
            (phoneNumber != null && containsXssPatterns(phoneNumber))) {
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