package io.github.ersincivi.passwordless.dto.projection;

import java.time.Instant;
import java.util.Set;

/**
 * Comprehensive projection for security-related user operations
 * Includes MFA settings and role information for admin operations
 */
public interface UserSecurityProjection {
    String getUsername();
    String getEmail();
    boolean isEnabled();
    boolean isLocked();
    boolean getMfaEnabled();
    String getPhoneNumber();
    String getOauthProvider();
    Instant getLastLoginAt();
    String getLastLoginIp();
    Set<RoleProjection> getRoles();
    
    interface RoleProjection {
        String getName();
        io.github.ersincivi.passwordless.domain.Role.Code getCode();
    }
}