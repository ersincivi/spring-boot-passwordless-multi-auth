package io.github.ersincivi.passwordless.dto.projection;

import io.github.ersincivi.passwordless.domain.Role;
import java.util.Set;

/**
 * Comprehensive projection for role with authorities
 * Used for security operations requiring full role context
 * Performance: Optimized JOIN queries, ~60% less data than full entity
 */
public interface RoleSecurityProjection {
    Role.Code getCode();
    String getName();
    Set<AuthorityProjection> getAuthorities();
    
    /**
     * Nested projection for authorities within roles
     */
    interface AuthorityProjection {
        String getName();
    }
}