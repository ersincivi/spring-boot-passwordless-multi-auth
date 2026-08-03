package io.github.ersincivi.passwordless.dto.projection;

public interface UserMfaProjection {
    String getUsername();
    Boolean getMfaEnabled();
    String getMfaSecret();
    String getPhoneNumber();
    String getEmail();
    String getLastLoginIp();
    boolean isEnabled();
    boolean isLocked();
}