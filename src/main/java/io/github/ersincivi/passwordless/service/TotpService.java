package io.github.ersincivi.passwordless.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Enhanced TOTP Service with comprehensive security features Includes rate
 * limiting, backup codes, audit logging, and Redis integration
 */
@Service
public class TotpService {

    private static final Logger logger = LoggerFactory.getLogger(TotpService.class);

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private SecurityAuditService securityAuditService;

    // Configuration constants
    private static final String ISSUER_NAME = "Passwordless Multi-Auth";
    private static final int TIME_STEP_SIZE_IN_MILLIS = 30000; // 30 seconds
    private static final int WINDOW_SIZE = 1; // Allow 1 step before/after
    private static final int CODE_DIGITS = 6;
    private static final int MAX_VERIFICATION_ATTEMPTS = 50; // Per 5 minutes
    private static final int BACKUP_CODES_COUNT = 10;

    // Redis key prefixes
    private static final String TOTP_ATTEMPTS_KEY = "totp_attempts:";
    private static final String BACKUP_CODES_KEY = "backup_codes:";
    private static final String USED_CODES_KEY = "used_totp_codes:";

    private final GoogleAuthenticator authenticator;
    private final SecureRandom secureRandom = new SecureRandom();

    public TotpService() {
        // Configure GoogleAuthenticator with enhanced security
        GoogleAuthenticatorConfig config = new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder()
                .setTimeStepSizeInMillis(TIME_STEP_SIZE_IN_MILLIS)
                .setWindowSize(WINDOW_SIZE)
                .setCodeDigits(CODE_DIGITS)
                .build();

        this.authenticator = new GoogleAuthenticator(config);
    }

    /**
     * Create new TOTP credentials with enhanced security
     */
    public TotpSetupResult createCredentials(String username) {
        try {
            GoogleAuthenticatorKey key = authenticator.createCredentials();
            String secret = key.getKey();
            String totpUri = buildTotpAuthUrl(username, secret);

            if (totpUri == null) {
                logger.error("TOTP Auth URL is null while generating credentials for user: {}", username);
                return new TotpSetupResult(false, null, null, null, "Failed to generate TOTP credentials");
            }

            String encodedTotpUri = URLEncoder.encode(totpUri, StandardCharsets.UTF_8.toString());

            // Generate backup codes
            List<String> backupCodes = generateBackupCodes();

            // Store backup codes in Redis
            storeBackupCodes(username, backupCodes);

            // Log TOTP setup initiation
            Map<String, Object> details = new HashMap<>();
            details.put("username", username);
            details.put("backupCodesGenerated", backupCodes.size());
            details.put("setupTime", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));

            securityAuditService.logAdminAction(
                    username, "TOTP_SETUP_INITIATED", username, "SUCCESS",
                    "SYSTEM", details);

            return new TotpSetupResult(true, secret, encodedTotpUri, backupCodes, null);

        } catch (Exception e) {
            logger.error("Error creating TOTP credentials for user: {}", username);
            return new TotpSetupResult(false, null, null, null, "Failed to generate TOTP credentials");
        }
    }

    /**
     * Verify TOTP code with rate limiting and security features
     */
    public TotpVerificationResult verifyCode(String username, String secret, String codeInput, String ipAddress, String userAgent) {
        if (username == null || secret == null || codeInput == null) {
            return new TotpVerificationResult(false, "Missing required parameters", false);
        }

        // Check rate limiting
        if (!checkRateLimit(username, ipAddress)) {
            // Log rate limit violation
            Map<String, Object> details = new HashMap<>();
            details.put("username", username);
            details.put("codeAttempt", codeInput.length() > 0 ? "*".repeat(codeInput.length()) : "empty");
            details.put("reason", "rate_limit_exceeded");

            securityAuditService.logSecurityViolation(
                    username, "TOTP_RATE_LIMIT_EXCEEDED", "TOTP verification rate limit exceeded",
                    ipAddress, userAgent, details);

            return new TotpVerificationResult(false, "Too many verification attempts. Please try again later.", false);
        }

        try {
            int code = Integer.parseInt(codeInput.trim());

            // Check if code was recently used to prevent replay attacks
            if (isCodeRecentlyUsed(username, code)) {
                incrementAttemptCount(username, ipAddress);
                return new TotpVerificationResult(false, "Code has already been used recently", false);
            }

            // Verify the TOTP code
            boolean isValid = authenticator.authorize(secret, code);

            if (isValid) {
                // Mark code as used
                markCodeAsUsed(username, code);

                // Reset rate limiting counter on successful verification
                resetAttemptCount(username, ipAddress);

                // Log successful verification
                Map<String, Object> details = new HashMap<>();
                details.put("username", username);
                details.put("verificationTime", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));

                securityAuditService.logAuthenticationEvent(
                        username, "TOTP_VERIFICATION_SUCCESS", "SUCCESS",
                        ipAddress, userAgent, details);

                return new TotpVerificationResult(true, "Code verified successfully", false);
            } else {
                // Increment attempt count on failure
                incrementAttemptCount(username, ipAddress);

                // Log failed verification
                Map<String, Object> details = new HashMap<>();
                details.put("username", username);
                details.put("codeAttempt", "*".repeat(codeInput.length()));
                details.put("reason", "invalid_code");

                securityAuditService.logAuthenticationEvent(
                        username, "TOTP_VERIFICATION_FAILED", "FAILURE",
                        ipAddress, userAgent, details);

                return new TotpVerificationResult(false, "Invalid verification code", false);
            }

        } catch (NumberFormatException e) {
            incrementAttemptCount(username, ipAddress);
            return new TotpVerificationResult(false, "Invalid code format", false);
        } catch (Exception e) {
            logger.error("Error verifying TOTP code for user: {}", username, e);
            return new TotpVerificationResult(false, "Verification error. Please try again.", false);
        }
    }

    /**
     * Verify backup code
     */
    public TotpVerificationResult verifyBackupCode(String username, String backupCode, String ipAddress, String userAgent) {
        if (username == null || backupCode == null || backupCode.trim().isEmpty()) {
            return new TotpVerificationResult(false, "Backup code is required", true);
        }

        // Check rate limiting
        if (!checkRateLimit(username, ipAddress)) {
            return new TotpVerificationResult(false, "Too many verification attempts. Please try again later.", true);
        }

        try {
            List<String> backupCodes = getBackupCodes(username);
            String trimmedCode = backupCode.trim().toUpperCase();

            if (backupCodes.contains(trimmedCode)) {
                // Remove the used backup code
                backupCodes.remove(trimmedCode);
                storeBackupCodes(username, backupCodes);

                // Reset rate limiting counter
                resetAttemptCount(username, ipAddress);

                // Log successful backup code usage
                Map<String, Object> details = new HashMap<>();
                details.put("username", username);
                details.put("backupCodeUsed", trimmedCode.substring(0, 2) + "***");
                details.put("remainingCodes", backupCodes.size());

                securityAuditService.logAuthenticationEvent(
                        username, "BACKUP_CODE_USED", "SUCCESS",
                        ipAddress, userAgent, details);

                return new TotpVerificationResult(true, "Backup code accepted", true);
            } else {
                incrementAttemptCount(username, ipAddress);

                // Log failed backup code attempt
                Map<String, Object> details = new HashMap<>();
                details.put("username", username);
                details.put("invalidBackupCode", backupCode.length() > 2 ? backupCode.substring(0, 2) + "***" : "***");

                securityAuditService.logAuthenticationEvent(
                        username, "BACKUP_CODE_FAILED", "FAILURE",
                        ipAddress, userAgent, details);

                return new TotpVerificationResult(false, "Invalid backup code", true);
            }

        } catch (Exception e) {
            logger.error("Error verifying backup code for user: {}", username, e);
            return new TotpVerificationResult(false, "Verification error. Please try again.", true);
        }
    }

    /**
     * Get remaining backup codes for user
     */
    public List<String> getBackupCodes(String username) {
        try {
            String backupCodesKey = BACKUP_CODES_KEY + username;
            String codesJson = redisTemplate.opsForValue().get(backupCodesKey);

            if (codesJson != null) {
                @SuppressWarnings("unchecked")
                List<String> codes = objectMapper.readValue(codesJson, List.class);
                return codes != null ? codes : new ArrayList<>();
            }

            return new ArrayList<>();

        } catch (Exception e) {
            logger.error("Error retrieving backup codes for user: {}", username, e);
            return new ArrayList<>();
        }
    }

    /**
     * Generate new backup codes for user
     */
    public List<String> regenerateBackupCodes(String username, String ipAddress) {
        try {
            List<String> newBackupCodes = generateBackupCodes();
            storeBackupCodes(username, newBackupCodes);

            // Log backup codes regeneration
            Map<String, Object> details = new HashMap<>();
            details.put("username", username);
            details.put("newCodesGenerated", newBackupCodes.size());

            securityAuditService.logAdminAction(
                    username, "BACKUP_CODES_REGENERATED", username, "SUCCESS",
                    ipAddress, details);

            return newBackupCodes;

        } catch (Exception e) {
            logger.error("Error regenerating backup codes for user: {}", username, e);
            return new ArrayList<>();
        }
    }

    public String buildTotpAuthUrl(String accountName, String secret) {
        try {
            String rawLabel = ISSUER_NAME + ": " + accountName;
            String encodedLabel = URLEncoder.encode(rawLabel, StandardCharsets.UTF_8.toString());
            String finalLabel = encodedLabel.replace("+", "%20");
            String issuer = URLEncoder.encode(ISSUER_NAME, StandardCharsets.UTF_8.toString());
            return "otpauth://totp/" + finalLabel + "?secret=" + secret + "&issuer=" + issuer + "&digits=" + CODE_DIGITS + "&period=" + (TIME_STEP_SIZE_IN_MILLIS / 1000);
        } catch (Exception e) {
            logger.error("Error building OTP auth URL for account: {}", accountName, e);
            return null;
        }
    }

    /**
     * Get TOTP status and statistics for user
     */
    public Map<String, Object> getTotpStatus(String username) {
        Map<String, Object> status = new HashMap<>();

        try {
            // Get backup codes count
            List<String> backupCodes = getBackupCodes(username);
            status.put("backupCodesRemaining", backupCodes.size());
            status.put("hasBackupCodes", !backupCodes.isEmpty());

            // Get attempt count
            String attemptsKey = TOTP_ATTEMPTS_KEY + username;
            String attempts = redisTemplate.opsForValue().get(attemptsKey);
            int attemptCount = attempts != null ? Integer.parseInt(attempts) : 0;
            status.put("recentAttempts", attemptCount);
            status.put("maxAttempts", MAX_VERIFICATION_ATTEMPTS);
            status.put("rateLimited", attemptCount >= MAX_VERIFICATION_ATTEMPTS);

            status.put("issuer", ISSUER_NAME);
            status.put("codeDigits", CODE_DIGITS);
            status.put("timeStep", TIME_STEP_SIZE_IN_MILLIS / 1000);

        } catch (Exception e) {
            logger.error("Error getting TOTP status for user: {}", username, e);
            status.put("error", "Failed to retrieve TOTP status");
        }

        return status;
    }

    // Private helper methods
    private boolean checkRateLimit(String username, String ipAddress) {
        String attemptsKey = TOTP_ATTEMPTS_KEY + username + ":" + ipAddress;
        String attempts = redisTemplate.opsForValue().get(attemptsKey);
        int attemptCount = attempts != null ? Integer.parseInt(attempts) : 0;
        return attemptCount < MAX_VERIFICATION_ATTEMPTS;
    }

    private void incrementAttemptCount(String username, String ipAddress) {
        String attemptsKey = TOTP_ATTEMPTS_KEY + username + ":" + ipAddress;
        Long count = redisTemplate.opsForValue().increment(attemptsKey);
        if (count == 1) {
            redisTemplate.expire(attemptsKey, 5, TimeUnit.MINUTES); // Reset every 5 minutes
        }
    }

    private void resetAttemptCount(String username, String ipAddress) {
        String attemptsKey = TOTP_ATTEMPTS_KEY + username + ":" + ipAddress;
        redisTemplate.delete(attemptsKey);
    }

    private List<String> generateBackupCodes() {
        List<String> codes = new ArrayList<>();
        for (int i = 0; i < BACKUP_CODES_COUNT; i++) {
            // Generate 8-character alphanumeric backup codes
            StringBuilder code = new StringBuilder();
            for (int j = 0; j < 8; j++) {
                int random = secureRandom.nextInt(36);
                if (random < 10) {
                    code.append((char) ('0' + random));
                } else {
                    code.append((char) ('A' + random - 10));
                }
            }
            codes.add(code.toString());
        }
        return codes;
    }

    private void storeBackupCodes(String username, List<String> backupCodes) {
        try {
            String backupCodesKey = BACKUP_CODES_KEY + username;
            String codesJson = objectMapper.writeValueAsString(backupCodes);
            redisTemplate.opsForValue().set(backupCodesKey, codesJson, 365, TimeUnit.DAYS); // Store for 1 year
        } catch (JsonProcessingException e) {
            logger.error("Error storing backup codes for user: {}", username, e);
        }
    }

    private boolean isCodeRecentlyUsed(String username, int code) {
        String usedCodeKey = USED_CODES_KEY + username + ":" + code;
        return Boolean.TRUE.equals(redisTemplate.hasKey(usedCodeKey));
    }

    private void markCodeAsUsed(String username, int code) {
        String usedCodeKey = USED_CODES_KEY + username + ":" + code;
        redisTemplate.opsForValue().set(usedCodeKey, "used", 90, TimeUnit.SECONDS); // Prevent replay for 90 seconds
    }

    // Data classes
    public static class TotpSetupResult {

        private final boolean success;
        private final String secret;
        private final String qrCodeUrl;
        private final List<String> backupCodes;
        private final String error;

        public TotpSetupResult(boolean success, String secret, String qrCodeUrl, List<String> backupCodes, String error) {
            this.success = success;
            this.secret = secret;
            this.qrCodeUrl = qrCodeUrl;
            this.backupCodes = backupCodes;
            this.error = error;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getSecret() {
            return secret;
        }

        public String getQrCodeUrl() {
            return qrCodeUrl;
        }

        public List<String> getBackupCodes() {
            return backupCodes;
        }

        public String getError() {
            return error;
        }
    }

    public static class TotpVerificationResult {

        private final boolean valid;
        private final String message;
        private final boolean isBackupCode;

        public TotpVerificationResult(boolean valid, String message, boolean isBackupCode) {
            this.valid = valid;
            this.message = message;
            this.isBackupCode = isBackupCode;
        }

        public boolean isValid() {
            return valid;
        }

        public String getMessage() {
            return message;
        }

        public boolean isBackupCode() {
            return isBackupCode;
        }
    }
}
