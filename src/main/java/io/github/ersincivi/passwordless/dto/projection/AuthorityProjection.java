package io.github.ersincivi.passwordless.dto.projection;

/**
 * Lightweight projection for authority information
 * Optimized for permission checking and security operations
 * Performance: ~90% less data compared to full Authority entity
 */
public interface AuthorityProjection {
    String getName();
}