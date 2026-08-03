package io.github.ersincivi.passwordless.security;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * An Authentication implementation that holds a Magic Link token.
 * 
 * LSP Compliance: This token follows the same pattern as UsernamePasswordAuthenticationToken,
 * making it interchangeable with other authentication tokens in the Spring Security framework.
 *
 * This token has two states:
 * 1. Unauthenticated (created by the Filter): Holds the token string from the URL
 *    as its "credentials". The principal is null.
 * 2. Authenticated (created by the Provider): Holds the CustomUserDetails as
 *    its "principal" and has authorities. The credentials (token) are cleared.
 */
public class MagicLinkAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal; // Will be CustomUserDetails when authenticated
    private final Object credentials; // Will be the token String when unauthenticated

    /**
     * Constructor for an *unauthenticated* token, created by the MagicLinkAuthenticationFilter.
     *
     * @param token The raw token string from the /auth/verify request.
     */
    public MagicLinkAuthenticationToken(String token) {
        super((Collection<GrantedAuthority>) null); // No authorities when unauthenticated
        this.principal = null;
        this.credentials = token;
        setAuthenticated(false);
    }

    /**
     * Constructor for an *authenticated* token, created by the MagicLinkAuthenticationProvider.
     *
     * @param principal   The verified CustomUserDetails object.
     * @param authorities The authorities granted to this user.
     */
    public MagicLinkAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities); // Grant authorities
        this.principal = principal;
        this.credentials = null; // Clear credentials (token is consumed)
        setAuthenticated(true); // Mark as authenticated
    }

    /**
     * @return The credentials (the token string) for the AuthenticationProvider to validate.
     */
    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    /**
     * @return The principal (the CustomUserDetails) after successful authentication.
     */
    @Override
    public Object getPrincipal() {
        return this.principal;
    }
}
