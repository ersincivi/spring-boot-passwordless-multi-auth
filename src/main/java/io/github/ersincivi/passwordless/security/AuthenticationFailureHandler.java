package io.github.ersincivi.passwordless.security;

import io.github.ersincivi.passwordless.service.AccountLockoutService;
import io.github.ersincivi.passwordless.service.CaptchaService;
import io.github.ersincivi.passwordless.service.SecurityAuditService;
import io.github.ersincivi.passwordless.service.WebI18nMessageService;
import io.github.ersincivi.passwordless.service.MagicLinkService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Custom authentication failure handler that implements account lockout functionality
 */
@Component
public class AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationFailureHandler.class);

    @Autowired
    private AccountLockoutService accountLockoutService;
    
    @Autowired
    private SecurityAuditService securityAuditService;
    
    @Autowired
    private CaptchaService captchaService;
    
    @Autowired
    private WebI18nMessageService webI18nMessageService;
    
    @Autowired(required = false)
    private MagicLinkService magicLinkService;
    
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                      AuthenticationException exception) throws IOException, ServletException {
        
        // Try to get username from different sources:
        // 1. Form parameter (for username/password login)
        String username = request.getParameter("username");
        
        // 2. MagicLink token parameter (for MagicLink authentication)
        // Note: We can't easily get the email from an expired/invalid token,
        // so we'll just handle it gracefully without triggering account lockout
        String token = request.getParameter("token");
        boolean isMagicLinkAuth = token != null && request.getRequestURI().contains("/auth/verify");
        
        String errorMessage = webI18nMessageService.getMessage("login.invalid.credentials", "Authentication failed", request);
        String userAgent = request.getHeader("User-Agent");

        log.debug("Authentication failure: username={}, magicLink={}", username, isMagicLinkAuth);
        
        // Handle MagicLink authentication failures differently
        // (invalid/expired tokens should not trigger account lockout)
        if (isMagicLinkAuth) {
            // For MagicLink, we don't have a username from an expired token
            // Just show a friendly error message without account lockout
            if (exception instanceof BadCredentialsException) {
                errorMessage = webI18nMessageService.getMessage("login.magiclink.error.token.invalid", 
                    "Login link is invalid or expired", request);
            }
            
            // Log the failed attempt without username
            securityAuditService.logSecurityViolation(
                "UNKNOWN", "MAGICLINK_TOKEN_INVALID", "Invalid or expired MagicLink token", 
                request.getRemoteAddr(), userAgent, securityAuditService.extractRequestInfo(request));
            
            // Encode error message and redirect
            String encodedError = URLEncoder.encode(errorMessage, StandardCharsets.UTF_8);
            setDefaultFailureUrl("/login?error=true&message=" + encodedError);
            super.onAuthenticationFailure(request, response, exception);
            return;
        }
        
        if (username != null && !username.trim().isEmpty()) {
            
            // Check if account is already locked
            if (accountLockoutService.isAccountLocked(username)) {
                long remainingTime = accountLockoutService.getRemainingLockoutTime(username);
                errorMessage = webI18nMessageService.getMessage("login.account.locked.time", 
                    new Object[]{remainingTime}, 
                    String.format("Account is locked. Try again in %d minutes.", remainingTime), 
                    request);
                
                // Log locked account attempt
                securityAuditService.logAuthenticationEvent(
                    username, "LOGIN_ATTEMPT_LOCKED", "FAILED", request.getRemoteAddr(), userAgent,
                    securityAuditService.extractRequestInfo(request));
                    
            } else if (exception instanceof BadCredentialsException) {
                // Record failed attempt for bad credentials
                int previousAttempts = accountLockoutService.getFailedAttempts(username);
                accountLockoutService.recordFailedAttempt(username);

                // Check if this attempt triggered a lockout
                if (accountLockoutService.isAccountLocked(username)) {
                    long lockoutTime = accountLockoutService.getRemainingLockoutTime(username);
                    errorMessage = webI18nMessageService.getMessage("login.account.locked.attempts", 
                        new Object[]{lockoutTime}, 
                        String.format("Too many failed attempts. Account locked for %d minutes.", lockoutTime), 
                        request);
                    
                    // Log account lockout event
                    securityAuditService.logAccountLockoutEvent(
                        username, "LOCKOUT_TRIGGERED", request.getRemoteAddr(), previousAttempts + 1,
                        securityAuditService.extractRequestInfo(request));
                } else {
                    if (previousAttempts > 0) {
                        int remainingAttempts = accountLockoutService.getRemainingAttempts(username);
                        errorMessage = webI18nMessageService.getMessage("login.invalid.credentials.attempts", 
                            new Object[]{remainingAttempts}, 
                            String.format("Invalid credentials. %d attempts remaining.", remainingAttempts), 
                            request);
                    } else {
                        errorMessage = webI18nMessageService.getMessage("login.invalid.credentials", 
                            "Invalid credentials.", request);
                    }

                    // Log failed authentication attempt
                    securityAuditService.logAuthenticationEvent(
                        username, "LOGIN_ATTEMPT", "FAILED", request.getRemoteAddr(), userAgent,
                        securityAuditService.extractRequestInfo(request));
                    
                    // Record failed attempt for CAPTCHA triggering
                    boolean captchaRequired = captchaService.recordFailedAttempt(username, request.getRemoteAddr(), userAgent);
                    if (captchaRequired) {
                        // Use localized CAPTCHA required message
                        String captchaMessage = webI18nMessageService.getMessage("login.captcha.required", 
                            "Security verification required due to multiple failed attempts", request);
                        String encodedCaptchaError = URLEncoder.encode(captchaMessage, StandardCharsets.UTF_8);
                        // Redirect to login with CAPTCHA requirement indicator
                        setDefaultFailureUrl("/login?error=true&captcha=required&message=" + encodedCaptchaError);
                        super.onAuthenticationFailure(request, response, exception);
                        return;
                    }
                }
            } else if (exception instanceof LockedException) {
                // Account is locked for other reasons (e.g., admin locked)
                errorMessage = webI18nMessageService.getMessage("login.account.admin.locked", 
                    "Account is locked. Please contact administrator.", request);
                
                // Log admin locked account attempt
                securityAuditService.logAuthenticationEvent(
                    username, "LOGIN_ATTEMPT_ADMIN_LOCKED", "FAILED", request.getRemoteAddr(), userAgent,
                    securityAuditService.extractRequestInfo(request));
            }
        } else {
            // Missing username error message
            errorMessage = webI18nMessageService.getMessage("login.username.missing", 
                "Username is required for login.", request);
                
            // Log attempt with missing username
            securityAuditService.logSecurityViolation(
                "UNKNOWN", "MISSING_USERNAME", "Login attempt without username", 
                request.getRemoteAddr(), userAgent, securityAuditService.extractRequestInfo(request));
        }
        
        // Encode error message for URL
        String encodedError = URLEncoder.encode(errorMessage, StandardCharsets.UTF_8);
        
        // Set default failure URL with error message
        setDefaultFailureUrl("/login?error=true&message=" + encodedError);
        
        // Call parent implementation
        super.onAuthenticationFailure(request, response, exception);
    }
    
}