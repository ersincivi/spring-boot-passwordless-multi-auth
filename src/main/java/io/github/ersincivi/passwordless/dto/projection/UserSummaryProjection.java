package io.github.ersincivi.passwordless.dto.projection;

import java.time.Instant;

/**
 * Lightweight projection for user listings and summaries
 * Optimized for dashboard and administrative views
 */
public interface UserSummaryProjection {
    String getUsername();
    String getEmail();
    boolean isEnabled();
    boolean isLocked();
    Instant getCreatedAt();
    Instant getLastLoginAt();
}