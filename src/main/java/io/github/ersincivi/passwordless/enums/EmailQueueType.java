package io.github.ersincivi.passwordless.enums;

public enum EmailQueueType {
    // RESET_PASSWORD,
    // RESET_PASSWORD_CONFIRMATION,
    VERIFY_OTP,
    VERIFY_GEO,
    VERIFY_MFA_EMAIL,
    GEO_ALERT,  // Alert for login from different country (informational only)
    MAGICLINK_WEB,  // MagicLink for web authentication
    MAGICLINK_API   // MagicLink for API/mobile authentication
}
