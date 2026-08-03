package io.github.ersincivi.passwordless.dto;

import java.time.Instant;

/**
 * DTO for Login response: short-lived JWT access token plus rotating refresh token.
 */
public record LoginResponse(String token, Instant expiresAt, String refreshToken, Instant refreshTokenExpiresAt) {

}
