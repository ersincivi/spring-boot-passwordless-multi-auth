package io.github.ersincivi.passwordless.dto.projection;

/**
 * Optimized projection for user authentication operations
 * Fetches only essential fields needed for login validation
 */
public interface UserLoginProjection {
    String getUsername();
    boolean isEnabled();
    boolean isLocked();
}