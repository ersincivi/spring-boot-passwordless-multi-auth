package io.github.ersincivi.passwordless.dto;

/**
 * DTO for MfaVerify request
 */
public record MfaVerifyRequest(String username, String code) {

}
