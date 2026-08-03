package io.github.ersincivi.passwordless.security;

import io.github.ersincivi.passwordless.domain.CustomUserDetails;
import io.github.ersincivi.passwordless.domain.User;
import io.github.ersincivi.passwordless.service.MagicLinkService;
import io.github.ersincivi.passwordless.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

/**
 * The "brain" for Magic Link authentication.
 * 
 * LSP Compliance: This Provider follows the same contract as other AuthenticationProviders
 * (e.g., DaoAuthenticationProvider for OAuth2). It produces the same CustomUserDetails principal
 * that all other authentication flows produce, ensuring interchangeability.
 *
 * This Provider is registered with the AuthenticationManager and knows
 * how to handle the MagicLinkAuthenticationToken.
 * It contains all logic previously in MagicLinkWebController.verifyMagicLink.
 * 
 * Key Improvements:
 * - Delegates to AuthenticationManager (LSP compliance)
 * - Produces unified CustomUserDetails principal
 * - Allows AuthenticationSuccessHandler to run (GeoIpService, audit logging)
 * - Centralizes account status checks
 * - Removes duplicated 2FA logic (TotpFilter handles it)
 */
@Component
public class MagicLinkAuthenticationProvider implements AuthenticationProvider {

    private static final Logger log = LoggerFactory.getLogger(MagicLinkAuthenticationProvider.class);

    private final MagicLinkService magicLinkService;
    private final UserDetailsService userDetailsService;
    private final UserService userService;

    public MagicLinkAuthenticationProvider(MagicLinkService magicLinkService,
                                          UserDetailsService userDetailsService,
                                          UserService userService) {
        this.magicLinkService = magicLinkService;
        this.userDetailsService = userDetailsService;
        this.userService = userService;
    }

    /**
     * This is where the actual authentication happens.
     * Called by the AuthenticationManager when a MagicLinkAuthenticationToken is submitted.
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 1. Get the token string from the unauthenticated token
        String token = (String) authentication.getCredentials();
        
        log.debug("MagicLink Provider: Authenticating token");

        // 2. Verify the token (Logic moved from Controller)
        // This service returns the email if valid/consumed, or null if invalid.
        String email = magicLinkService.verifyAndConsumeWebToken(token);
        if (email == null) {
            log.warn("MagicLink Provider: Invalid or expired token");
            // This exception will be handled by AuthenticationFailureHandler
            throw new BadCredentialsException("Invalid or expired Magic Link token.");
        }

        log.info("MagicLink Provider: Token verified for email: {}", email);

        // 3. Load the Unified Principal (LSP RESTORED)
        // IMPORTANT: MagicLink stores EMAIL in Redis, but UserDetailsService expects USERNAME.
        // Solution: First get the User by email, then load CustomUserDetails by username.
        
        // Step 3a: Get the User entity by email
        User user = userService.getFullUserByEmail(email)
            .orElseThrow(() -> {
                log.error("MagicLink Provider: User not found for email: {}", email);
                return new BadCredentialsException("User not found for email: " + email);
            });
        
        log.debug("MagicLink Provider: Found user {} for email: {}", user.getUsername(), email);
        
        // Step 3b: Load CustomUserDetails by username (same as OAuth2, OIDC flows)
        // This ensures LSP compliance - the principal type is consistent across all auth methods.
        CustomUserDetails userDetails;
        try {
            userDetails = (CustomUserDetails) userDetailsService.loadUserByUsername(user.getUsername());
        } catch (Exception e) {
            log.error("MagicLink Provider: Failed to load user details for username: {}", user.getUsername(), e);
            throw new BadCredentialsException("User details not found for username: " + user.getUsername());
        }

        // 4. Perform account status checks (Logic moved from Controller)
        if (userDetails == null) {
            log.error("MagicLink Provider: User details null for email: {}", email);
            throw new BadCredentialsException("User details not found for email: " + email);
        }
        
        if (!userDetails.isEnabled()) {
            log.warn("MagicLink Provider: Account disabled for email: {}", email);
            throw new DisabledException("User account is disabled.");
        }
        
        if (!userDetails.isAccountNonLocked()) {
            log.warn("MagicLink Provider: Account locked for email: {}", email);
            throw new LockedException("User account is locked.");
        }

        // 5. SUCCESS
        // We do NOT check for TOTP here. We let the TotpFilter do its job
        // after this provider succeeds. This centralizes 2FA logic and maintains LSP.
        // 
        // The TotpFilter will:
        // - Check if mfaEnabled = true
        // - If true: Set PENDING_USERNAME and redirect to /totp
        // - If false: Allow the request through
        
        log.info("MagicLink Provider: Authentication successful for email: {}", email);
        
        // Return a *new*, *authenticated* token containing our unified Principal.
        // This is the same principal type (CustomUserDetails) that OAuth2 and OIDC produce.
        return new MagicLinkAuthenticationToken(userDetails, userDetails.getAuthorities());
    }

    /**
     * Tells the AuthenticationManager that this Provider *only*
     * understands MagicLinkAuthenticationToken.
     * 
     * LSP Compliance: This follows the standard AuthenticationProvider contract.
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return MagicLinkAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
