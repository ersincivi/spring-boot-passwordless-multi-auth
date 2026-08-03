package io.github.ersincivi.passwordless.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * The "entry point" for Magic Link authentication.
 * 
 * LSP Compliance: This filter follows the same pattern as other authentication filters
 * (e.g., OAuth2LoginAuthenticationFilter). It intercepts a specific URL pattern,
 * creates an authentication token, and delegates to the AuthenticationManager.
 *
 * This filter intercepts the GET /auth/verify?token=... request,
 * creates an unauthenticated MagicLinkAuthenticationToken,
 * and passes it to the AuthenticationManager for processing.
 *
 * Key Benefits:
 * - Integrates with Spring Security filter chain (LSP compliance)
 * - Triggers AuthenticationSuccessHandler on success (GeoIpService, audit logging)
 * - Triggers AuthenticationFailureHandler on failure (security audit)
 * - Allows TotpFilter to handle 2FA centrally
 * - No manual SecurityContext manipulation
 * 
 * This class is instantiated as a @Bean in SecurityConfig.
 */
@Component
public class MagicLinkAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final Logger log = LoggerFactory.getLogger(MagicLinkAuthenticationFilter.class);

    // We only want this filter to trigger on this specific path and method.
    private static final RequestMatcher DEFAULT_REQUEST_MATCHER =
            PathPatternRequestMatcher.withDefaults().matcher("/auth/verify");

    /**
     * Constructor for the MagicLink authentication filter.
     * 
     * @param authenticationManager The central authentication manager that will
     *                             delegate to our MagicLinkAuthenticationProvider.
     */
    public MagicLinkAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(DEFAULT_REQUEST_MATCHER, authenticationManager);
        
        log.info("MagicLinkAuthenticationFilter initialized for path: /auth/verify");
    }

    /**
     * This method is called when the /auth/verify URL is hit.
     * 
     * LSP Compliance: This follows the same pattern as other authentication filters.
     * We create an unauthenticated token and delegate to the AuthenticationManager.
     * 
     * @param request  The HTTP request containing the token parameter
     * @param response The HTTP response
     * @return An authenticated Authentication object if successful
     * @throws AuthenticationException if authentication fails
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        log.debug("MagicLinkAuthenticationFilter: Processing /auth/verify request");

        // 1. Extract the token from the request parameter
        String token = request.getParameter("token");
        if (token == null) {
            token = ""; // Let the Provider handle the "empty token" error
            log.warn("MagicLinkAuthenticationFilter: No token parameter found in request");
        }

        log.info("MagicLinkAuthenticationFilter: Attempting authentication with token");

        // 2. Create the unauthenticated token
        // This is analogous to how UsernamePasswordAuthenticationFilter creates
        // an unauthenticated UsernamePasswordAuthenticationToken.
        MagicLinkAuthenticationToken authRequest = new MagicLinkAuthenticationToken(token.trim());

        // 3. Delegate to the AuthenticationManager
        // The manager will:
        // - Find our MagicLinkAuthenticationProvider (because it `supports` this token)
        // - Call the provider's `authenticate` method
        // - Return the authenticated token with CustomUserDetails principal
        // 
        // If successful:
        // - AbstractAuthenticationProcessingFilter calls our AuthenticationSuccessHandler
        // - TotpFilter will then check for mfaEnabled and handle 2FA if needed
        // 
        // If failed:
        // - AbstractAuthenticationProcessingFilter calls our AuthenticationFailureHandler
        // - Audit logging and security events are triggered
        
        log.debug("MagicLinkAuthenticationFilter: Delegating to AuthenticationManager");
        
        return this.getAuthenticationManager().authenticate(authRequest);
    }
}
