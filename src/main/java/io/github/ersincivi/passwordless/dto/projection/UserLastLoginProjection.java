package io.github.ersincivi.passwordless.dto.projection;

public interface UserLastLoginProjection {
    String getUsername();
    String getEmail();
    boolean isEnabled();
    String getLastLoginIp();
}