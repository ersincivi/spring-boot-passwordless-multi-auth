package io.github.ersincivi.passwordless.security;

import java.util.Collections;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * T3.1: Restricted authentication used between primary authentication
 * (Email OTP / MagicLink / OAuth2) and successful TOTP verification.
 *
 * The token is authenticated (so the /totp page is reachable) but carries
 * NO authorities, so the authorization layer denies access to protected
 * resources until MFA completes. TotpWebController upgrades it to a full
 * authentication after a successful TOTP verification.
 */
public class PreMfaAuthenticationToken extends UsernamePasswordAuthenticationToken {

    public PreMfaAuthenticationToken(UserDetails principal) {
        super(principal, null, Collections.emptyList());
    }
}
