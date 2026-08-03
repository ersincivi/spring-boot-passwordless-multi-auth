package io.github.ersincivi.passwordless.controller.web;

import io.github.ersincivi.passwordless.domain.User;
import io.github.ersincivi.passwordless.domain.CustomUserDetails;
import io.github.ersincivi.passwordless.service.UserService;
import io.github.ersincivi.passwordless.service.WebI18nMessageService;
import io.github.ersincivi.passwordless.service.TotpService;
import io.github.ersincivi.passwordless.service.SecurityAuditService;

import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.http.HttpServletRequest;

import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.github.ersincivi.passwordless.utils.QrCodeGenerator.generateQrCodeImage;

@Controller
public class SettingsController {

    private static final Logger logger = LoggerFactory.getLogger(SettingsController.class);

    private final TotpService totpService;
    private final UserService userService;
    private final SecurityAuditService securityAuditService;
    private final WebI18nMessageService webI18nMessageService;

    public SettingsController(TotpService totpService, UserService userService,
            SecurityAuditService securityAuditService,
            WebI18nMessageService webI18nMessageService) {
        this.totpService = totpService;
        this.userService = userService;
        this.securityAuditService = securityAuditService;
        this.webI18nMessageService = webI18nMessageService;
    }

    @GetMapping("/settings")
    public String settings(@AuthenticationPrincipal CustomUserDetails customUser, Principal principal, Model model, HttpServletRequest request) {
        try {

            logger.info("Check user: {}", principal.getName());

            // The principal carries the User loaded at login time; MFA may have
            // been toggled since then, so always re-read the current state from
            // the database (a stale copy here both mis-renders the status badge
            // and regenerates setup credentials after enrollment).
            User user = userService.getFullUserByUsername(customUser.getUsername())
                    .orElse(customUser.getUser());
            model.addAttribute("user", user);

            // If TOTP is not enabled, create setup credentials
            if (!Boolean.TRUE.equals(user.getMfaEnabled())) {
                logger.info("Creating TOTP credentials for user: {} (TOTP enabled: {})", customUser.getUsername(), user.getMfaEnabled());

                try {
                    TotpService.TotpSetupResult setupResult = totpService.createCredentials(customUser.getUsername());

                    logger.info("TOTP setup result for user {}: success={}, secret={}, qrUrl={}, error={}",
                            customUser.getUsername(),
                            setupResult.isSuccess(),
                            setupResult.getSecret() != null ? "Present(" + setupResult.getSecret().length() + ")" : "NULL",
                            setupResult.getQrCodeUrl() != null ? "Present(" + setupResult.getQrCodeUrl().length() + ")" : "NULL",
                            setupResult.getError()
                    );

                    if (setupResult.isSuccess()) {
                        model.addAttribute("provisionKey", setupResult.getSecret());
                        model.addAttribute("totpUri", setupResult.getQrCodeUrl());
                        // Never log the otpauth:// URL - it embeds the TOTP secret
                        logger.info("Successfully added TOTP setup attributes to model for user: {}", customUser.getUsername());
                    } else {
                        logger.error("Failed to create TOTP credentials for user: {}, error: {}", customUser.getUsername(), setupResult.getError());
                        model.addAttribute("totpSetupError", setupResult.getError());
                    }
                } catch (Exception e) {
                    logger.error("Exception creating TOTP credentials for user: {}", customUser.getUsername(), e);
                    model.addAttribute("totpSetupError", "Failed to generate TOTP setup: " + e.getMessage());
                }
            } else {
                // If TOTP is enabled, show backup codes
                List<String> backupCodes = totpService.getBackupCodes(customUser.getUsername());
                model.addAttribute("backupCodes", backupCodes);

                // Add TOTP status information
                Map<String, Object> totpStatus = totpService.getTotpStatus(customUser.getUsername());
                model.addAttribute("totpStatus", totpStatus);
            }

            // Log settings page access
            String ipAddress = request.getRemoteAddr();
            String userAgent = request.getHeader("User-Agent");

            Map<String, Object> details = new HashMap<>();
            details.put("username", customUser.getUsername());
            details.put("mfaEnabled", user.getMfaEnabled());
            details.put("userAgent", userAgent);

            securityAuditService.logAdminAction(
                    customUser.getUsername(), "SETTINGS_PAGE_ACCESSED", customUser.getUsername(), "SUCCESS",
                    ipAddress, details);

            return "settings";

        } catch (Exception e) {
            logger.error("Error loading settings page for user: {}", principal.getName(), e);
            model.addAttribute("error", "Failed to load settings. Please try again.");
            return "settings";
        }
    }

    @GetMapping(value = "/settings/qr-code", produces = MediaType.IMAGE_PNG_VALUE)
    @ResponseBody
    public byte[] getQrCodeImage(@RequestParam String totpUri) throws Exception {
        return generateQrCodeImage(totpUri, 250, 250);
    }

    /**
     * Enable TOTP authentication
     */
    @PostMapping("/settings/mfa-totp/enable")
    public String enableTotp(Principal principal, @RequestParam("secret") String secret,
            @RequestParam("code") String codeInput, HttpServletRequest request) {
        try {
            // Get username - works for both email and OAuth2 users
            String username = principal.getName();

            logger.info("Enabling TOTP for user: {}", username);
            
            // Verify TOTP code first (secret is provided from form)
            // This will verify the code without needing user data
            String ipAddress = request.getRemoteAddr();
            String userAgent = request.getHeader("User-Agent");

            // Verify TOTP code
            TotpService.TotpVerificationResult result = totpService.verifyCode(
                    username, secret, codeInput, ipAddress, userAgent);

            if (!result.isValid()) {
                logger.warn("Failed TOTP enable attempt for user: {}, reason: {}", username, result.getMessage());
                return "redirect:/settings?totpError";
            }
            
            // TOTP code is valid, now enable it
            // Use updateMfaTotp which doesn't need the user projection
            
            // Enable TOTP for user using UserService
            int mfaTotp = userService.updateMfaTotp(username, secret, true);
            logger.debug("TOTP MFA update result for user {}: {} rows affected", username, mfaTotp);

            if (mfaTotp > 0) {
                // Log successful TOTP enablement
                Map<String, Object> details = new HashMap<>();
                details.put("username", username);
                details.put("totpEnabled", true);

                securityAuditService.logAdminAction(
                        username, "TOTP_ENABLED", username, "SUCCESS",
                        ipAddress, details);

                return "redirect:/settings?totpEnabled";
            }

            logger.warn("Failed to update TOTP settings for user: {}", username);
            return "redirect:/settings?totpError";

        } catch (Exception e) {
            logger.error("Error enabling TOTP for user: {}", principal.getName(), e);
            return "redirect:/settings?totpError";
        }
    }

    /**
     * Disable TOTP authentication
     */
    @PostMapping("/settings/mfa-totp/disable")
    public String disableTotp(Principal principal, HttpServletRequest request) {
        try {
            // Get username - works for both email and OAuth2 users
            String username = principal.getName();
            String ipAddress = request.getRemoteAddr();

            // Disable TOTP using UserService
            int mfaTotp = userService.updateMfaTotp(username, null, false);
            logger.debug("TOTP MFA disable result for user {}: {} rows affected", username, mfaTotp);

            // Log TOTP disablement
            Map<String, Object> details = new HashMap<>();
            details.put("username", username);
            details.put("totpEnabled", false);

            securityAuditService.logAdminAction(
                    username, "TOTP_DISABLED", username, "SUCCESS",
                    ipAddress, details);

            return "redirect:/settings?totpDisabled";

        } catch (Exception e) {
            logger.error("Error disabling TOTP for user: {}", principal.getName(), e);
            return "redirect:/settings?error";
        }
    }

    /**
     * Regenerate backup codes
     */
    @PostMapping("/settings/mfa-totp/regenerate-backup-codes")
    public String regenerateBackupCodes(Principal principal, HttpServletRequest request) {
        try {
            User user = userService.getFullUserByUsername(principal.getName()).orElseThrow();
            String ipAddress = request.getRemoteAddr();

            // Check if TOTP is enabled
            if (!Boolean.TRUE.equals(user.getMfaEnabled())) {
                return "redirect:/settings?error";
            }

            // Regenerate backup codes
            List<String> newBackupCodes = totpService.regenerateBackupCodes(user.getUsername(), ipAddress);

            if (!newBackupCodes.isEmpty()) {
                return "redirect:/settings?backupCodesRegenerated";
            } else {
                return "redirect:/settings?error";
            }

        } catch (Exception e) {
            logger.error("Error regenerating backup codes for user: {}", principal.getName(), e);
            return "redirect:/settings?error";
        }
    }

    /**
     * Get User entity from authentication principal.
     * 
     * With unified CustomUserDetails principal, this is now simplified.
     * No more type checking - all auth methods return CustomUserDetails.
     */
    private User getCurrentUser(Authentication authentication) {
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        String username = userDetails.getUsername();
        return userService.getFullUserByUsername(username).orElseThrow(
            () -> new UsernameNotFoundException("User not found: " + username)
        );
    }

    // Utility methods moved to UserService - these are now redundant
    // private boolean isValidPhoneNumber(String phone) { ... }
    // private String maskPhoneNumber(String phone) { ... }
}
