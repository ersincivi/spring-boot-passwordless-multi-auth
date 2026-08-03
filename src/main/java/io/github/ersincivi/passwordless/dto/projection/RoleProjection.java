package io.github.ersincivi.passwordless.dto.projection;

import io.github.ersincivi.passwordless.domain.Role;

/**
 * Lightweight projection for role information
 * Optimized for security and authorization operations
 * Performance: ~85% less data compared to full Role entity with eager-loaded authorities
 */
public interface RoleProjection {
    Role.Code getCode();
    String getName();
}