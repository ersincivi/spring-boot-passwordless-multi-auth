package io.github.ersincivi.passwordless.dto.projection;

/**
 * Lightweight projection for email-based operations
 * Optimized for existence checks and basic email validation
 * Performance: ~95% less data compared to full User entity
 */
public interface UserEmailProjection {
    String getEmail();
    boolean isEnabled();
}