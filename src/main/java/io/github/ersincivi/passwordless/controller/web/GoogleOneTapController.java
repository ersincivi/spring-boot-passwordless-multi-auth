package io.github.ersincivi.passwordless.controller.web;

import io.github.ersincivi.passwordless.domain.CustomUserDetails;
import io.github.ersincivi.passwordless.domain.Role;
import io.github.ersincivi.passwordless.domain.User;
import io.github.ersincivi.passwordless.repository.RoleRepository;
import io.github.ersincivi.passwordless.repository.UserRepository;
import io.github.ersincivi.passwordless.security.PreMfaAuthenticationToken;
import io.github.ersincivi.passwordless.service.ApiI18nMessageService;
import io.github.ersincivi.passwordless.service.CustomOidcUserService;
import io.github.ersincivi.passwordless.service.GeoAlertService;
import io.github.ersincivi.passwordless.service.GeoIpService;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Google One Tap login controller.
 *
 * <p>Like every other authentication method here — e-mail OTP, OAuth2, OIDC —
 * it produces a {@code CustomUserDetails} principal, which is what keeps the
 * flows interchangeable downstream.
 */

@RestController
@RequestMapping("/auth")
public class GoogleOneTapController {

    private static final Logger log = LoggerFactory.getLogger(GoogleOneTapController.class);

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String googleClientId;

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final CustomOidcUserService customOidcUserService;
    private final ApiI18nMessageService apiMessageService;
    private final GeoIpService geoIpService;
    private final GeoAlertService geoAlertService;

    public GoogleOneTapController(UserRepository userRepository,
                                   RoleRepository roleRepository,
                                   CustomOidcUserService customOidcUserService,
                                   ApiI18nMessageService apiMessageService,
                                   GeoIpService geoIpService,
                                   GeoAlertService geoAlertService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.customOidcUserService = customOidcUserService;
        this.apiMessageService = apiMessageService;
        this.geoIpService = geoIpService;
        this.geoAlertService = geoAlertService;
    }

    /**
     * Google One Tap Login endpoint
     * Verifies the JWT token from Google and authenticates the user
     */
    @PostMapping("/google-one-tap")
    public ResponseEntity<Map<String, Object>> handleGoogleOneTap(
            @RequestBody Map<String, String> payload,
            HttpServletRequest request) {
        
        log.info("Google One Tap: Received authentication request from IP: {}", request.getRemoteAddr());
        
        try {
            String credential = payload.get("credential");
            if (credential == null || credential.isEmpty()) {
                log.warn("Google One Tap: Missing credential in request payload");
                return ResponseEntity.badRequest()
                        .body(apiMessageService.createDetailedLocalizedErrorResponse(
                            "login.google.error.missing.credential",
                            null,
                            HttpStatus.BAD_REQUEST.value(),
                            request
                        ));
            }
            
            log.debug("Google One Tap: Received credential token (length: {})", credential.length());

            // Verify the Google ID token
            log.debug("Google One Tap: Verifying token with client ID: {}", googleClientId);
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(
                    new NetHttpTransport(), 
                    GsonFactory.getDefaultInstance())
                    .setAudience(Collections.singletonList(googleClientId))
                    .build();

            GoogleIdToken idToken = null;
            try {
                idToken = verifier.verify(credential);
            } catch (Exception verifyException) {
                log.error("Google One Tap: Token verification failed", verifyException);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(apiMessageService.createDetailedLocalizedErrorResponse(
                            "login.google.error.token.verification.failed",
                            new Object[]{verifyException.getMessage() != null ? verifyException.getMessage() : "Invalid token format"},
                            HttpStatus.UNAUTHORIZED.value(),
                            request
                        ));
            }
            
            if (idToken == null) {
                log.warn("Google One Tap: Invalid ID token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(apiMessageService.createLocalizedErrorResponse(
                            "login.google.error.invalid.token",
                            HttpStatus.UNAUTHORIZED.value(),
                            request
                        ));
            }

            GoogleIdToken.Payload tokenPayload = idToken.getPayload();
            
            // Extract user information
            String email = tokenPayload.getEmail();
            String name = (String) tokenPayload.get("name");
            String googleUserId = tokenPayload.getSubject();
            Boolean emailVerified = tokenPayload.getEmailVerified();

            log.info("Google One Tap: Received authentication for email: {}", email);

            if (!Boolean.TRUE.equals(emailVerified)) {
                log.warn("Google One Tap: Email not verified for {}", email);
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(apiMessageService.createLocalizedErrorResponse(
                            "login.google.error.email.not.verified",
                            HttpStatus.FORBIDDEN.value(),
                            request
                        ));
            }

            // Find or create user
            User user = userRepository.findByEmail(email).orElse(null);
            final boolean isNewUser = (user == null);
            
            if (isNewUser) {
                // Create new user
                user = new User();
                user.setUsername(email);
                user.setEmail(email);
                user.setEnabled(true);
                user.setOauthProvider("google");
                user.setOauthSubject(googleUserId);
                user.setMfaEnabled(false);
                
                // Initialize roles with USER role
                user.setRoles(new HashSet<>());
                final User finalNewUser = user;
                roleRepository.findByCode(Role.Code.USER).ifPresent(role -> {
                    finalNewUser.getRoles().add(role);
                    log.info("Google One Tap: Added USER role to new user {}", email);
                });
                
                log.info("Google One Tap: Creating new user for {}", email);
            } else {
                // Update existing user's OAuth info
                user.setOauthProvider("google");
                user.setOauthSubject(googleUserId);
                
                // Ensure user has at least USER role
                if (user.getRoles() == null || user.getRoles().isEmpty()) {
                    user.setRoles(new HashSet<>());
                    final User finalExistingUser = user;
                    roleRepository.findByCode(Role.Code.USER).ifPresent(role -> {
                        finalExistingUser.getRoles().add(role);
                        log.info("Google One Tap: Added USER role to existing user {}", email);
                    });
                }
                
                log.info("Google One Tap: Found existing user {}", email);
            }

            // Update user name and profile picture from Google ID token
            if (name != null && !name.isEmpty()) {
                user.setName(name);
            }
            
            String pictureUrl = (String) tokenPayload.get("picture");
            if (pictureUrl != null && !pictureUrl.isEmpty()) {
                user.setProfileImage(pictureUrl);
            }

            // Capture the previous login IP BEFORE overwriting it - the
            // geo-change check below compares against it.
            final String previousLoginIp = user.getLastLoginIp();

            // Update login tracking
            user.setLastLoginIp(request.getRemoteAddr());
            user.setLastLoginAt(Instant.now());

            // Save user
            final User savedUser = userRepository.save(user);
            
            log.info("Google One Tap: User {} saved successfully (new user: {})", email, isNewUser);

            // ========== CRITICAL: Create UNIFIED CustomUserDetails Principal ==========
            // Build authorities from user roles (both role authorities and ROLE_ prefix)
            Set<GrantedAuthority> authorities = new HashSet<>();
            if (savedUser.getRoles() != null && !savedUser.getRoles().isEmpty()) {
                savedUser.getRoles().forEach(role -> {
                    // Add role-specific authorities
                    role.getAuthorities().forEach(authority -> 
                        authorities.add(new SimpleGrantedAuthority(authority.getName()))
                    );
                    // Add ROLE_ prefix for role-based checks
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getCode().name()));
                });
                log.debug("Google One Tap: Built authorities for user {}: {}", email, authorities);
            } else {
                // Fallback: add USER role authority if no roles found
                authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
                log.warn("Google One Tap: No roles found for user {}, using fallback ROLE_USER", email);
            }
            
            // Create Google One Tap attributes map (similar to OAuth2)
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("sub", googleUserId);
            attributes.put("email", email);
            attributes.put("name", name);
            attributes.put("picture", pictureUrl);
            attributes.put("email_verified", emailVerified);
            attributes.put("provider", "google-one-tap");
            
            // Create UNIFIED CustomUserDetails principal (implements UserDetails, OAuth2User, OidcUser)
            // This ensures consistency with all other authentication methods
            CustomUserDetails userDetails = new CustomUserDetails(
                savedUser,
                authorities,
                attributes,  // OAuth2 attributes from Google
                null,        // No OIDC ID token for One Tap
                null         // No OIDC UserInfo for One Tap
            );
            
            log.debug("Google One Tap: Created CustomUserDetails principal for {}", email);

            // T3.1 parity with every other login method: if the account has
            // TOTP enabled, One Tap must NOT complete authentication - it only
            // establishes a restricted pre-MFA context and sends the browser
            // to /totp for the second factor (TotpWebController upgrades it).
            boolean totpRequired = Boolean.TRUE.equals(savedUser.getMfaEnabled());

            SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
            HttpSession session = request.getSession(true);

            if (totpRequired) {
                session.setAttribute("PENDING_USERNAME", savedUser.getUsername());
                session.setAttribute("PENDING_AUTH_TIME", System.currentTimeMillis());
                securityContext.setAuthentication(new PreMfaAuthenticationToken(userDetails));
                log.info("Google One Tap: TOTP required for user {}, restricted pre-MFA context set", email);
            } else {
                securityContext.setAuthentication(
                        new UsernamePasswordAuthenticationToken(userDetails, null, authorities));
                log.info("Google One Tap: Successfully authenticated user {} with CustomUserDetails principal", email);
            }

            SecurityContextHolder.setContext(securityContext);
            session.setAttribute(
                    HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                    securityContext);

            // Geo-change parity with AuthenticationSuccessHandler: One Tap
            // bypasses that handler, so run the same country comparison here.
            if (geoIpService.isAvailable() && savedUser.getEmail() != null) {
                String currentCountry = geoIpService.lookupCountryIso(request.getRemoteAddr()).orElse(null);
                String previousCountry = previousLoginIp != null
                        ? geoIpService.lookupCountryIso(previousLoginIp).orElse(null) : null;
                if (currentCountry != null && previousCountry != null && !currentCountry.equals(previousCountry)) {
                    log.info("Google One Tap: Country changed from {} to {} for user {}, sending alert...",
                            previousCountry, currentCountry, email);
                    geoAlertService.sendGeoAlert(
                            savedUser.getEmail(),
                            savedUser.getUsername(),
                            session.getId(),
                            currentCountry,
                            previousCountry,
                            request.getRemoteAddr(),
                            apiMessageService.getCurrentLocale(request));
                }
            }

            // Prepare response
            return ResponseEntity.ok(
                apiMessageService.createSuccessResponse(
                    "login.google.success",
                    Map.of(
                        "redirectUrl", totpRequired ? "/totp" : "/",
                        "user", Map.of(
                            "email", email,
                            "name", name != null ? name : email
                        )
                    ),
                    request
                )
            );

        } catch (Exception e) {
            log.error("Google One Tap: Authentication error", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(apiMessageService.createDetailedLocalizedErrorResponse(
                        "login.google.error.authentication.failed",
                        new Object[]{e.getMessage()},
                        HttpStatus.INTERNAL_SERVER_ERROR.value(),
                        request
                    ));
        }
    }
}
