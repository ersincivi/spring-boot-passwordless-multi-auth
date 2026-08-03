package io.github.ersincivi.passwordless.security;

import io.github.ersincivi.passwordless.service.AccountLockoutService;
import io.github.ersincivi.passwordless.service.CaptchaService;
import io.github.ersincivi.passwordless.service.SecurityAuditService;
import io.github.ersincivi.passwordless.service.GeoIpService;
import io.github.ersincivi.passwordless.service.GeoAlertService;
import io.github.ersincivi.passwordless.service.UserService;
import io.github.ersincivi.passwordless.service.WebI18nMessageService;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import io.github.ersincivi.passwordless.domain.CustomUserDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

/**
 * Unified Authentication Success Handler
 * 
 * Handles authentication success for ALL login methods:
 * - Email OTP (Passwordless) / Magiclink
 * - Google OAuth2/OIDC
 * - GitHub OAuth2
 * 
 * IMPORTANT: All authentication methods now return CustomUserDetails principal.
 * No more type checking or casting needed - LSP compliance achieved.
 */

@Component
public class AuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationSuccessHandler.class);
    
    @Autowired
    private AccountLockoutService accountLockoutService;
    
    @Autowired
    private SecurityAuditService securityAuditService;
    
    @Autowired
    private CaptchaService captchaService;
    
    @Autowired
    private GeoIpService geoIpService;
    
    @Autowired
    private GeoAlertService geoAlertService;
    
    @Autowired
    private UserService userService;
    
    @Autowired
    private WebI18nMessageService webI18nMessageService;
    
    /**
     * Initialize the handler with default target URL.
     * This ensures users are redirected to home page after successful login
     * when there's no saved request to return to.
     */
    @PostConstruct
    public void init() {
        // Set default target URL for all authentication methods
        setDefaultTargetUrl("/");
        // Allow saved request redirect (don't always use default)
        setAlwaysUseDefaultTargetUrl(false);
        log.info("AuthenticationSuccessHandler initialized with defaultTargetUrl=/");
    }
    
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                      Authentication authentication) throws IOException, ServletException {
        try {
            log.info("===== AuthenticationSuccessHandler TRIGGERED =====");
            log.info("Authentication type: {}", authentication.getClass().getName());
            log.info("Principal type: {}", authentication.getPrincipal().getClass().getName());

            // Get the unified principal (always CustomUserDetails now)
            CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
            String username = userDetails.getUsername(); // Always email
            String userEmail = userDetails.getEmail();
            String userName = userDetails.getDisplayName();
            String profileImage = userDetails.getProfileImage();
            
            log.info("Unified principal - Username: {}, Email: {}, Display Name: {}, mfaEnabled: {}", username, userEmail, userName, userDetails.getUser().getMfaEnabled());
            
            // Determine login method from authentication type
            String loginMethod = "email";
            if (authentication instanceof OAuth2AuthenticationToken oauth2Token) {
                loginMethod = oauth2Token.getAuthorizedClientRegistrationId();
                log.info("OAuth2 authentication detected - Provider: {}", loginMethod);
            }
            
            log.info("AuthenticationSuccessHandler: About to check TOTP status for user: {}", username);
            
            // Check if TOTP is enabled for this user
            // IMPORTANT: Use data from CustomUserDetails to avoid transaction conflicts
            // The Provider already loaded the full User entity, so we don't need another query
            boolean totpEnabled = userDetails.getUser().getMfaEnabled() != null && userDetails.getUser().getMfaEnabled();
            
            log.info("AuthenticationSuccessHandler: mfaEnabled={} for user {}", totpEnabled, username);
        
        if (totpEnabled) {
            // TOTP is required - store pending username for TotpFilter
            log.info("AuthenticationSuccessHandler: TOTP required for user {}, storing PENDING_USERNAME", username);
            request.getSession(true).setAttribute("PENDING_USERNAME", username);
            request.getSession().setAttribute("PENDING_AUTH_TIME", System.currentTimeMillis());

            // T3.1: Downgrade the security context to a restricted pre-MFA authentication
            // (no authorities) until TOTP verification completes. TotpWebController
            // upgrades it back to a full authentication after successful verification.
            SecurityContextHolder.getContext().setAuthentication(new PreMfaAuthenticationToken(userDetails));
            log.info("AuthenticationSuccessHandler: Downgraded to restricted pre-MFA authentication for user {}", username);
        } else {
            // TOTP not required - ensure PENDING_USERNAME is cleared
            log.info("AuthenticationSuccessHandler: TOTP not required for user {}, clearing PENDING_USERNAME", username);
            if (request.getSession(false) != null) {
                log.info("Removing PENDING_USERNAME and PENDING_AUTH_TIME from session...");
                request.getSession().removeAttribute("PENDING_USERNAME");
                request.getSession().removeAttribute("PENDING_AUTH_TIME");
            }
        }
        
        log.info("AuthenticationSuccessHandler: Storing user data in session...");
        
        // Store user data in session for Thymeleaf access (both OAuth and email logins)
        log.info(">>> Storing data in session <<<");
        if (loginMethod != null) {
            request.getSession().setAttribute("login_method", loginMethod);
            log.info("Set session.login_method = {}", loginMethod);
        }
        if (userEmail != null) {
            request.getSession().setAttribute("user_email", userEmail);
            log.info("Set session.user_email = {}", userEmail);
        }
        if (userName != null) {
            request.getSession().setAttribute("user_name", userName);
            log.info("Set session.user_name = {}", userName);
        }
        if (profileImage != null) {
            request.getSession().setAttribute("user_profileImage", profileImage);
            log.info("Set session.user_profileImage = {}", profileImage);
        }
        
        log.info("Session ID: {}", request.getSession().getId());
        log.info("Session attributes set - method: {}, email: {}, name: {}, image: {}", 
                  loginMethod, userEmail, userName, profileImage);
        
        log.info("AuthenticationSuccessHandler: Processing post-authentication tasks...");
        
        if (username != null && !username.trim().isEmpty()) {
            log.info("AuthenticationSuccessHandler: Clearing account lockout and captcha for user: {}", username);
            accountLockoutService.clearFailedAttempts(username);
            
            // Clear CAPTCHA requirement after successful authentication
            captchaService.clearCaptchaRequirement(username);
            
            // Log successful authentication
            String userAgent = request.getHeader("User-Agent");
            
            log.info("AuthenticationSuccessHandler: Logging authentication event...");
            
            securityAuditService.logAuthenticationEvent(
                username, "LOGIN_SUCCESS", "SUCCESS", request.getRemoteAddr(), userAgent,
                securityAuditService.extractRequestInfo(request));
            
            log.info("AuthenticationSuccessHandler: Checking for GeoIP changes...");
            
            // Check for geo location change and send alert email (informational only, no verification required)
            if (geoIpService.isAvailable()) {
                log.info("AuthenticationSuccessHandler: GeoIP service available, checking location change...");
                // Use data from CustomUserDetails to avoid transaction conflicts
                String userEmailForAlert = userDetails.getEmail();
                String lastLoginIp = userDetails.getUser().getLastLoginIp();
                
                if (userEmailForAlert != null) {
                    String currentCountry = geoIpService.lookupCountryIso(request.getRemoteAddr()).orElse(null);
                    String previousCountry = lastLoginIp != null ? geoIpService.lookupCountryIso(lastLoginIp).orElse(null) : null;
                    
                    // Send informational alert if country changed
                    if (currentCountry != null && previousCountry != null && !currentCountry.equals(previousCountry)) {
                        log.info("AuthenticationSuccessHandler: Username {} and email: {}. Country changed from {} to {}, sending alert...", username, userEmail, previousCountry, currentCountry);
                        String sessionId = request.getSession(true).getId();
                        geoAlertService.sendGeoAlert(
                            userEmailForAlert, 
                            username, 
                            sessionId, 
                            currentCountry, 
                            previousCountry, 
                            request.getRemoteAddr(),
                            webI18nMessageService.getCurrentLocale(request)
                        );
                    } else {
                        log.info("AuthenticationSuccessHandler: No country change detected (current: {}, previous: {})", currentCountry, previousCountry);
                    }
                } else {
                    log.info("AuthenticationSuccessHandler: User email is null, skipping GeoIP alert");
                }
            } else {
                log.info("AuthenticationSuccessHandler: GeoIP service not available");
            }
            
            // Log session creation
            // String sessionId = request.getSession(true).getId();
            // securityAuditService.logSessionEvent(
            //     username, "SESSION_CREATED", sessionId, clientIP,
            //     securityAuditService.extractRequestInfo(request));
        }
        
        log.info("AuthenticationSuccessHandler: Calling super.onAuthenticationSuccess to handle redirect...");
        
        // CRITICAL FIX: Manually save the SecurityContext to the session.
        // The SecurityContextPersistenceFilter, which normally handles this, might not be
        // saving the context correctly in this specific custom filter flow before the redirect.
        // This explicit save ensures the authenticated context is available for the next request.
        SecurityContext context = SecurityContextHolder.getContext();
        request.getSession(true).setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
        log.info("AuthenticationSuccessHandler: Explicitly saved SecurityContext to session to ensure persistence across redirect.");

        // Continue with default success handling
        super.onAuthenticationSuccess(request, response, authentication);
        
        log.info("AuthenticationSuccessHandler: SUCCESS - Redirect completed");
        
        } catch (Exception e) {
            log.error("AuthenticationSuccessHandler: EXCEPTION occurred during authentication success handling", e);
            throw e;
        }
    }
    
}