package io.github.ersincivi.passwordless.dto;

import java.util.Objects;

public record UserProfileResponse(
    String username,
    String email,
    boolean enabled,
    String lastLoginIp,
    String locale
) {
    
    public UserProfileResponse {
        Objects.requireNonNull(username, "username is required");
        Objects.requireNonNull(email, "email is required");
        Objects.requireNonNull(locale, "locale is required");
        
        // Locale validation following secure-project specification
        if (!locale.matches("^[a-z]{2}(-[A-Z]{2})?$")) {
            throw new IllegalArgumentException("Invalid locale format");
        }
        
        // XSS prevention for user input fields
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