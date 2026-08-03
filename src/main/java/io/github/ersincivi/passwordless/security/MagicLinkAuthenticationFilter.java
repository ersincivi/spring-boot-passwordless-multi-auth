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
 * Entry point for MagicLink authentication.
 *
 * <p>Built on the same pattern as the other authentication filters, such as
 * {@code OAuth2LoginAuthenticationFilter}: it intercepts
 * {@code GET /auth/verify?token=...}, creates an unauthenticated
 * {@code MagicLinkAuthenticationToken}, and hands it to the
 * {@code AuthenticationManager}.
 *
 * <p>Sitting inside the Spring Security filter chain is what makes the
 * success and failure handlers fire — GeoIP anomaly detection and audit
 * logging on success, a security audit record on failure — lets
 * {@code TotpFilter} apply 2FA centrally, and keeps the
 * {@code SecurityContext} out of manual hands.
 *
 * <p>Registered as a bean in {@code SecurityConfig}.
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
     * Called when the /auth/verify URL is hit: builds an unauthenticated
     * token and delegates to the AuthenticationManager, the same way the
     * other authentication filters do.
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
