package io.github.ersincivi.passwordless.dto;

public record GitHubEmail(
    String email,
    boolean primary,
    boolean verified
) {}
