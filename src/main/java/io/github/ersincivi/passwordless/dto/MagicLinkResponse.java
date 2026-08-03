package io.github.ersincivi.passwordless.dto;

import java.time.Instant;

/**
 * DTO for MagicLink response
 */
public record MagicLinkResponse(
        String message,
        String email,
        int ttlSeconds,
        Instant expiresAt
) {
}
