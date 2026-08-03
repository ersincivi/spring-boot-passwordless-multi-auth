package io.github.ersincivi.passwordless.domain;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Unified Principal - Single authentication object for ALL login methods.
 * 
 * This class implements three core Spring Security interfaces simultaneously:
 * - UserDetails: For traditional/email-based authentication
 * - OAuth2User: For OAuth2 social login (Google, GitHub)
 * - OidcUser: For OpenID Connect login (Google)
 * 
 * Because every authentication flow resolves to this one type, controllers
 * never have to branch on which one produced the principal — the Liskov
 * substitution principle applied to authentication.
 * 
 * Authentication Methods Supported:
 * 1. Email OTP (Passwordless)
 * 2. MagicLink (Passwordless)
 * 3. Google OAuth2/OIDC
 * 4. GitHub OAuth2
 * 
 * @see <a href="update.md">Unified Principal Strategy Documentation</a>
 */
public class CustomUserDetails implements UserDetails, OAuth2User, OidcUser, Serializable {
    private static final long serialVersionUID = 1L;

    private final User user;
    private final Collection<? extends GrantedAuthority> authorities;
    private final Map<String, Object> attributes;
    private final OidcIdToken idToken;
    private final OidcUserInfo userInfo;

    /**
     * Constructor for Email OTP / Passwordless authentication.
     * Used by DefaultUserDetailsService for email-based login.
     * 
     * @param user The user entity from database
     * @param authorities The granted authorities/roles
     */
    public CustomUserDetails(User user, Collection<? extends GrantedAuthority> authorities) {
        this(user, authorities, Collections.emptyMap(), null, null);
    }

    /**
     * Main constructor for ALL authentication flows (Email OTP, OAuth2, OIDC).
     * 
     * @param user The user entity from database
     * @param authorities The granted authorities/roles
     * @param attributes OAuth2 attributes (empty for email OTP)
     * @param idToken OIDC ID token (null for OAuth2/Email)
     * @param userInfo OIDC user info (null for OAuth2/Email)
     */
    public CustomUserDetails(User user, Collection<? extends GrantedAuthority> authorities,
                             Map<String, Object> attributes, OidcIdToken idToken, OidcUserInfo userInfo) {
        this.user = user;
        this.authorities = authorities;
        // Make a serializable copy of attributes for session storage
        this.attributes = attributes != null ? new HashMap<>(attributes) : Collections.emptyMap();
        this.idToken = idToken;
        this.userInfo = userInfo;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    /**
     * PASSWORDLESS: Always returns null.
     * The system uses Email OTP and OAuth2/OIDC for authentication.
     * No passwords are stored in the database.
     */
    @Override
    public String getPassword() {
        return null; // Passwordless: No password stored
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !user.isLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return user.isEnabled();
    }

    // Additional methods to expose User properties
    public String getEmail() {
        return user.getEmail();
    }

    public String getUserName() {
        return user.getName();
    }

    public String getProfileImage() {
        return user.getProfileImage();
    }

    public User getUser() {
        return user;
    }

    /**
     * CRITICAL: Returns the username (email) for ALL authentication methods.
     * This ensures consistency across Email OTP, OAuth2, and OIDC logins.
     * 
     * Spring Security contract: getName() MUST return the username/principal identifier.
     * This is used throughout the application for authorization and security checks.
     * 
     * @return Always returns the email/username (never display name)
     */
    @Override
    public String getName() {
        return user.getUsername(); // Always return email/username for consistency
    }

    /**
     * Get the user's display name for UI rendering.
     * Falls back to username if display name is not set.
     * 
     * Use this method in templates: ${principal.displayName}
     * 
     * @return The display name or username as fallback
     */
    public String getDisplayName() {
        return user.getName() != null ? user.getName() : user.getUsername();
    }

    // ==================== OAuth2User Interface Implementation ====================

    /**
     * OAuth2User interface: Returns attributes from OAuth2 provider.
     * Empty map for Email OTP users.
     * 
     * @return OAuth2 attributes (email, name, picture, etc.)
     */
    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    // ==================== OidcUser Interface Implementation ====================

    /**
     * OidcUser interface: Returns claims from OIDC ID token.
     * Empty map for Email OTP and non-OIDC OAuth2 users.
     * 
     * @return OIDC claims from ID token
     */
    @Override
    public Map<String, Object> getClaims() {
        return idToken != null ? idToken.getClaims() : Collections.emptyMap();
    }

    /**
     * OidcUser interface: Returns the OIDC ID token.
     * Null for Email OTP and non-OIDC OAuth2 users.
     * 
     * @return The OIDC ID token or null
     */
    @Override
    public OidcIdToken getIdToken() {
        return idToken;
    }

    /**
     * OidcUser interface: Returns OIDC user info.
     * Null for Email OTP and non-OIDC OAuth2 users.
     * 
     * @return The OIDC user info or null
     */
    @Override
    public OidcUserInfo getUserInfo() {
        return userInfo;
    }

    // ==================== Helper Methods ====================

    /**
     * Check if this principal has OAuth2 attributes.
     * 
     * @return true if user logged in via OAuth2/OIDC
     */
    public boolean isOAuth2User() {
        return attributes != null && !attributes.isEmpty();
    }

    /**
     * Check if this principal has an OIDC ID token.
     * 
     * @return true if user logged in via OIDC (Google)
     */
    public boolean isOidcUser() {
        return idToken != null;
    }
}
