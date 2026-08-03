package io.github.ersincivi.passwordless.dto;

import java.time.Instant;
import java.util.Objects;

/**
 * Standardized API response record with internationalization support
 * Follows secure-project API response format: {error, status, message, locale, data, timestamp}
 * 
 * @param <T> Type of data payload
 */
public record ApiResponse<T>(
    boolean error,
    int status,
    String message,
    String locale,
    T data,
    Instant timestamp
) {
    
    public ApiResponse {
        Objects.requireNonNull(message, "message is required");
        Objects.requireNonNull(locale, "locale is required");
        Objects.requireNonNull(timestamp, "timestamp is required");
        
        // Locale validation following secure-project specification
        if (!locale.matches("^[a-z]{2}(-[A-Z]{2})?$")) {
            throw new IllegalArgumentException("Invalid locale format. Must match pattern: ^[a-z]{2}(-[A-Z]{2})?$");
        }
        
        // Status validation
        if (status < 100 || status > 599) {
            throw new IllegalArgumentException("Invalid HTTP status code");
        }
    }
    
    /**
     * Create successful API response
     */
    public static <T> ApiResponse<T> success(T data, String message, String locale) {
        return new ApiResponse<>(false, 200, message, locale, data, Instant.now());
    }
    
    /**
     * Create error API response
     */
    public static <T> ApiResponse<T> error(int status, String message, String locale) {
        return new ApiResponse<>(true, status, message, locale, null, Instant.now());
    }
    
    /**
     * Create error API response with data
     */
    public static <T> ApiResponse<T> error(int status, String message, String locale, T errorData) {
        return new ApiResponse<>(true, status, message, locale, errorData, Instant.now());
    }
}