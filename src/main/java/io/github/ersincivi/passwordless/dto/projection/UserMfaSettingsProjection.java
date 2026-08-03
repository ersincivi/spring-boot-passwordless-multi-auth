package io.github.ersincivi.passwordless.dto.projection;

public interface UserMfaSettingsProjection {
    String getUsername();
    String getMfaSecret();
    Boolean getMfaEnabled();
    String getPhoneNumber();
}
