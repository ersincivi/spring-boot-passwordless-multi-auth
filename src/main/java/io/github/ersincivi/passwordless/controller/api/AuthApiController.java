package io.github.ersincivi.passwordless.controller.api;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.github.ersincivi.passwordless.domain.CustomUserDetails;
import io.github.ersincivi.passwordless.domain.User;
import io.github.ersincivi.passwordless.dto.EmailQueueMessage;
import io.github.ersincivi.passwordless.dto.LoginResponse;
import io.github.ersincivi.passwordless.dto.MagicLinkRequest;
import io.github.ersincivi.passwordless.dto.MfaVerifyRequest;
import io.github.ersincivi.passwordless.dto.projection.UserMfaProjection;
import io.github.ersincivi.passwordless.enums.EmailQueueType;
import io.github.ersincivi.passwordless.security.TokenStore;
import io.github.ersincivi.passwordless.service.ApiI18nMessageService;
import io.github.ersincivi.passwordless.service.ApiLoginEventService;
import io.github.ersincivi.passwordless.service.EmailQueueService;
import io.github.ersincivi.passwordless.service.ExchangeCodeService;
import io.github.ersincivi.passwordless.service.JwtService;
import io.github.ersincivi.passwordless.service.MagicLinkService;
import io.github.ersincivi.passwordless.service.RefreshTokenService;
import io.github.ersincivi.passwordless.service.TotpService;
import io.github.ersincivi.passwordless.service.UserService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;

/**
 * REST API Authentication Controller - Passwordless Only
 * 
 * IMPORTANT: This controller has been factored to support PASSWORDLESS authentication only.
 * - MagicLink (Passwordless email-based authentication)
 * - OAuth2/OIDC Social Login (Google, GitHub)
 * - TOTP (Time-based One-Time Password) for MFA
 * 
 * For web-based authentication, see:
 * - MagicLinkWebController (MagicLink flow)
 * - OAuth2 configuration in SecurityConfig (Social login)
 */

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "Passwordless authentication endpoints for API/Mobile clients")
public class AuthApiController {

    private final JwtService jwtService;
    private final TokenStore tokenStore;
    private final TotpService totpService;
    private final UserService userService;
    private final ApiI18nMessageService apiI18nService;
    private final MagicLinkService magicLinkService;
    private final EmailQueueService emailQueueService;
    private final RefreshTokenService refreshTokenService;
    private final ExchangeCodeService exchangeCodeService;
    private final ApiLoginEventService apiLoginEventService;

    @Value("${app.base-url}")
    private String baseUrl;

    @Value("${app.mobile.callback-url:passwordless://auth/callback}")
    private String mobileCallbackUrl;

    public AuthApiController(JwtService jwtService, TokenStore tokenStore,
            TotpService totpService,
            UserService userService, ApiI18nMessageService apiI18nService,
            MagicLinkService magicLinkService,
            EmailQueueService emailQueueService,
            RefreshTokenService refreshTokenService,
            ExchangeCodeService exchangeCodeService,
            ApiLoginEventService apiLoginEventService) {
        this.jwtService = jwtService;
        this.tokenStore = tokenStore;
        this.totpService = totpService;
        this.userService = userService;
        this.apiI18nService = apiI18nService;
        this.magicLinkService = magicLinkService;
        this.emailQueueService = emailQueueService;
        this.refreshTokenService = refreshTokenService;
        this.exchangeCodeService = exchangeCodeService;
        this.apiLoginEventService = apiLoginEventService;
    }

    private record RefreshRequest(String refreshToken) {}

    private record LogoutRequest(String refreshToken) {}

    private record ExchangeRequest(String code) {}

    /**
     * ❌ REMOVED: Password-based login endpoint
     * 
     * This application now uses PASSWORDLESS authentication only.
     * Password-based /api/auth/login endpoint has been removed.
     * 
     * For API authentication, clients should:
     * 1. Request a MagicLink (POST /api/auth/email-magiclink/send)
     * 2. Open the emailed link in the browser; GET /api/auth/verify redirects
     *    (302) to the app scheme with a one-time exchange code
     * 3. Trade the code for a token pair via POST /api/auth/exchange
     * 4. Refresh via POST /api/auth/refresh; revoke via POST /api/auth/logout
     *
     * For MFA verification, use:
     * - /api/auth/totp/verify for TOTP codes
     */

    /**
     * Send MagicLink to email for API/mobile passwordless login
     * POST /api/auth/email-magiclink/send
     */
    @Operation(
        summary = "Send MagicLink",
        description = "Send a passwordless MagicLink to user's email for API/mobile authentication. " +
                     "The MagicLink token is single-use and expires after app.magiclink.api.ttl-seconds " +
                     "(default 120 seconds).",
        tags = {"Authentication"}
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "MagicLink sent successfully",
            content = @Content(mediaType = "application/json")),
        @ApiResponse(responseCode = "400", description = "Invalid email format or missing email",
            content = @Content(mediaType = "application/json")),
        @ApiResponse(responseCode = "500", description = "Email sending failed",
            content = @Content(mediaType = "application/json"))
    })
    @PostMapping("/email-magiclink/send")
    public ResponseEntity<?> sendApiMagicLink(
            @RequestBody MagicLinkRequest request, 
            HttpServletRequest http) {
        try {
            String email = request.email();

            if (email == null || email.isBlank()) {
                return ResponseEntity.badRequest()
                        .body(apiI18nService.createLocalizedErrorResponse(
                                "register.email.required",
                                HttpStatus.BAD_REQUEST.value(),
                                http
                        ));
            }

            // Validate email format
            if (!email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(apiI18nService.createLocalizedErrorResponse(
                                "register.email.invalid",
                                HttpStatus.BAD_REQUEST.value(), http));
            }

            // T3.3: Anti-enumeration - respond uniformly whether or not the account exists.
            // Only generate and send the link when the account actually exists.
            boolean userExists = userService.getFullUserByEmail(email).isPresent();
            if (!userExists) {
                return ResponseEntity.ok().body(
                        apiI18nService.createSuccessResponse(
                                "login.magiclink.sent",
                                Map.of(
                                        "email", email,
                                        "ttlSeconds", magicLinkService.getApiTtlSeconds(),
                                        "expiresAt", magicLinkService.calculateApiExpiration()
                                ),
                                http
                        ));
            }

            // Generate MagicLink token for API
            String token = magicLinkService.generateApiToken(email);
            
            // Build MagicLink URL (mobile app deep link or fallback web URL)
            String magicLinkUrl = baseUrl + "/api/auth/verify?token=" + token;
            
            // Get localized subject for email
            String subject = apiI18nService.getMessage("email.magiclink.api.subject", http);

            // Get current locale for email
            Locale locale = apiI18nService.getCurrentLocale(http);

            // Queue email with MagicLink
            EmailQueueMessage emailMessage = new EmailQueueMessage(
                    email, 
                    subject, 
                    magicLinkUrl,
                    EmailQueueType.MAGICLINK_API, 
                    locale
            );
            emailQueueService.enqueue(emailMessage);

            return ResponseEntity.ok().body(
                    apiI18nService.createSuccessResponse(
                            "login.magiclink.sent",
                            Map.of(
                                    "email", email,
                                    "ttlSeconds", magicLinkService.getApiTtlSeconds(),
                                    "expiresAt", magicLinkService.calculateApiExpiration()
                            ),
                            http
                    ));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(apiI18nService.createLocalizedErrorResponse(
                            "login.magiclink.error.send.failed",
                            HttpStatus.INTERNAL_SERVER_ERROR.value(), http));
        }
    }

    /**
     * Verify MagicLink token and return JWT for API authentication
     * GET /api/auth/verify?token=XYZ
     */
    @Operation(
        summary = "Verify MagicLink",
        description = "Verify MagicLink token from the email link. T4.1: This endpoint runs in the " +
                     "browser, so it redirects (302) to the mobile app scheme instead of returning JSON. " +
                     "On success the redirect carries a one-time exchange code (?code=...) which the app " +
                     "trades for a token pair via POST /api/auth/exchange. If TOTP is enabled, the redirect " +
                     "carries ?status=totp_required and the app must call POST /api/auth/totp/verify.",
        tags = {"Authentication"}
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "302", description = "Redirect to the app callback (success, TOTP required, or error status)",
            content = @Content)
    })
    @GetMapping("/verify")
    public ResponseEntity<?> verifyApiMagicLink(
            @Parameter(description = "MagicLink token from email", required = true)
            @RequestParam("token") String token,
            HttpServletRequest http) {
        try {
            if (token == null || token.isBlank()) {
                return appRedirect("status=error&reason=token_missing");
            }

            // Verify and consume token (one-time use)
            String email = magicLinkService.verifyAndConsumeApiToken(token);

            if (email == null) {
                apiLoginEventService.onLoginFailure(null, "magiclink_token_invalid", http);
                return appRedirect("status=error&reason=token_invalid");
            }

            // Find user by email
            User user = userService.getFullUserByEmail(email).orElse(null);

            if (user == null) {
                apiLoginEventService.onLoginFailure(null, "magiclink_user_not_found", http);
                return appRedirect("status=error&reason=user_not_found");
            }

            if (!user.isEnabled()) {
                apiLoginEventService.onLoginFailure(email, "account_disabled", http);
                return appRedirect("status=error&reason=account_disabled");
            }

            // T4.2: lockout parity with the web chain (AccountLockoutFilter)
            if (apiLoginEventService.isAccountLocked(user.getUsername())) {
                apiLoginEventService.onLoginFailure(user.getUsername(), "account_locked", http);
                return appRedirect("status=error&reason=account_locked");
            }

            // Check if TOTP is enabled
            boolean totpEnabled = userService.findUserMfaByUsername(user.getUsername())
                    .map(mfa -> Boolean.TRUE.equals(mfa.getMfaEnabled()))
                    .orElse(false);

            if (totpEnabled) {
                // TOTP required - the app shows the TOTP screen and calls /api/auth/totp/verify
                String userEmail = user.getEmail() != null ? user.getEmail() : "";
                return appRedirect("status=totp_required&username=" + urlEncode(user.getUsername())
                        + "&email=" + urlEncode(userEmail));
            }

            // Success - hand a one-time exchange code to the app
            String code = exchangeCodeService.issue(user.getUsername());
            return appRedirect("code=" + code);

        } catch (Exception e) {
            return appRedirect("status=error&reason=verification_failed");
        }
    }

    /**
     * T4.1: Exchange a one-time code (from the app-scheme redirect) for a token pair.
     * POST /api/auth/exchange
     */
    @Operation(
        summary = "Exchange code for tokens",
        description = "Trade the one-time exchange code received via the app-scheme redirect " +
                     "for a JWT access token + refresh token pair. The code is single use and " +
                     "expires after 60 seconds.",
        tags = {"Authentication"}
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Token pair returned",
            content = @Content(mediaType = "application/json")),
        @ApiResponse(responseCode = "400", description = "Missing exchange code",
            content = @Content(mediaType = "application/json")),
        @ApiResponse(responseCode = "401", description = "Invalid, expired or already used exchange code",
            content = @Content(mediaType = "application/json")),
        @ApiResponse(responseCode = "403", description = "Account disabled",
            content = @Content(mediaType = "application/json"))
    })
    @PostMapping("/exchange")
    public ResponseEntity<?> exchangeCode(@RequestBody ExchangeRequest request, HttpServletRequest http) {
        if (request == null || request.code() == null || request.code().isBlank()) {
            return ResponseEntity.badRequest()
                    .body(apiI18nService.createLocalizedErrorResponse(
                            "api.exchange.code.missing",
                            HttpStatus.BAD_REQUEST.value(), http));
        }

        var username = exchangeCodeService.consume(request.code());
        if (username.isEmpty()) {
            apiLoginEventService.onLoginFailure(null, "exchange_code_invalid", http);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(apiI18nService.createLocalizedErrorResponse(
                            "api.exchange.code.invalid",
                            HttpStatus.UNAUTHORIZED.value(), http));
        }

        User user = userService.getFullUserByEmail(username.get()).orElse(null);
        if (user == null || !user.isEnabled()) {
            apiLoginEventService.onLoginFailure(username.get(), "account_disabled", http);
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(apiI18nService.createLocalizedErrorResponse(
                            "login.email.error.account.disabled",
                            HttpStatus.FORBIDDEN.value(), http));
        }

        // T4.2: lockout parity with the web chain (AccountLockoutFilter)
        if (apiLoginEventService.isAccountLocked(user.getUsername())) {
            apiLoginEventService.onLoginFailure(user.getUsername(), "account_locked", http);
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(apiI18nService.createLocalizedErrorResponse(
                            "login.account.locked",
                            HttpStatus.FORBIDDEN.value(), http));
        }

        // T4.2: audit parity - lockout reset, LOGIN_SUCCESS event, geo-change alert
        apiLoginEventService.onLoginSuccess(user, "magiclink-api", http, apiI18nService.getCurrentLocale(http));

        return ResponseEntity.ok(apiI18nService.createSuccessResponse(
                "login.success", issueTokenPair(user.getUsername()), http));
    }

    private ResponseEntity<Void> appRedirect(String query) {
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(mobileCallbackUrl + "?" + query))
                .build();
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /**
     * Verify TOTP (Time-based One-Time Password) code.
     * Used for MFA verification after initial authentication.
     */
    @Operation(
        summary = "Verify TOTP",
        description = "Verify TOTP (Time-based One-Time Password) code for MFA. " +
                     "Used after MagicLink verification when TOTP is enabled for the user.",
        tags = {"Authentication"}
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "TOTP verified successfully, JWT returned",
            content = @Content(mediaType = "application/json")),
        @ApiResponse(responseCode = "400", description = "TOTP not enabled, invalid code, or verification error",
            content = @Content(mediaType = "application/json"))
    })
    @PostMapping("/totp/verify")
    public ResponseEntity<?> verifyTotp(@RequestBody MfaVerifyRequest request, HttpServletRequest http) {
        String ip = http.getRemoteAddr();
        UserMfaProjection userMfa = userService.findUserMfaByUsername(request.username()).orElse(null);
        if (userMfa == null || !Boolean.TRUE.equals(userMfa.getMfaEnabled()) || userMfa.getMfaSecret() == null) {
            return ResponseEntity.status(400).body(
                    apiI18nService.createLocalizedErrorResponse("api.totp.not.enabled", 400, http)
            );
        }

        // T4.2: lockout parity with the web chain (AccountLockoutFilter)
        if (apiLoginEventService.isAccountLocked(userMfa.getUsername())) {
            apiLoginEventService.onLoginFailure(userMfa.getUsername(), "account_locked", http);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(
                    apiI18nService.createLocalizedErrorResponse("login.account.locked", HttpStatus.FORBIDDEN.value(), http)
            );
        }

        String userAgent = http.getHeader("User-Agent");
        TotpService.TotpVerificationResult result;

        try {
            result = totpService.verifyCode(userMfa.getUsername(), userMfa.getMfaSecret(), request.code(), ip, userAgent);
        } catch (Exception e) {
            return ResponseEntity.status(400).body(
                    apiI18nService.createLocalizedErrorResponse("api.verification.error", 400, http)
            );
        }

        if (!result.isValid()) {
            apiLoginEventService.onLoginFailure(userMfa.getUsername(), "totp_invalid", http);
            return ResponseEntity.status(400).body(
                    apiI18nService.createLocalizedErrorResponse("api.invalid.code", 400, http)
            );
        }

        // T4.2: audit parity - lockout reset, LOGIN_SUCCESS event, geo-change alert
        User user = userService.getFullUserByEmail(request.username()).orElse(null);
        if (user != null) {
            apiLoginEventService.onLoginSuccess(user, "totp", http, apiI18nService.getCurrentLocale(http));
        }

        return ResponseEntity.ok(apiI18nService.createSuccessResponse(
                "login.success",
                issueTokenPair(request.username()),
                http
        ));
    }

    /**
     * Rotate a refresh token and return a new access/refresh token pair.
     * POST /api/auth/refresh
     */
    @Operation(
        summary = "Refresh access token",
        description = "Exchange a valid refresh token for a new access token and a new refresh token. " +
                     "The presented refresh token is invalidated (single-use rotation).",
        tags = {"Authentication"}
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "New token pair issued",
            content = @Content(mediaType = "application/json")),
        @ApiResponse(responseCode = "401", description = "Refresh token invalid, expired or already used",
            content = @Content(mediaType = "application/json"))
    })
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest request, HttpServletRequest http) {
        if (request == null || !StringUtils.hasText(request.refreshToken())) {
            return ResponseEntity.badRequest()
                    .body(apiI18nService.createLocalizedErrorResponse(
                            "api.refresh.token.missing", HttpStatus.BAD_REQUEST.value(), http));
        }

        return refreshTokenService.rotate(request.refreshToken())
                .<ResponseEntity<?>>map(rotation -> ResponseEntity.ok(
                        apiI18nService.createSuccessResponse(
                                "login.success",
                                issueTokenPair(rotation.username(), rotation.refreshToken()),
                                http)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(apiI18nService.createLocalizedErrorResponse(
                                "api.refresh.token.invalid", HttpStatus.UNAUTHORIZED.value(), http)));
    }

    /**
     * Logout: revoke the current access token and (optionally) the refresh token.
     * POST /api/auth/logout
     */
    @Operation(
        summary = "Logout",
        description = "Revoke the current access token (from the Authorization header) and " +
                     "optionally the refresh token passed in the request body.",
        tags = {"Authentication"}
    )
    @ApiResponse(responseCode = "204", description = "Tokens revoked")
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody(required = false) LogoutRequest request, HttpServletRequest http) {
        String header = http.getHeader("Authorization");
        if (StringUtils.hasText(header) && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            try {
                Claims claims = jwtService.parseToken(token).getPayload();
                revokeAccessToken(claims.getSubject(), claims.getId());
            } catch (ExpiredJwtException e) {
                // Allow logout with an expired access token
                revokeAccessToken(e.getClaims().getSubject(), e.getClaims().getId());
            } catch (JwtException | IllegalArgumentException ignored) {
                // Nothing to revoke for an unparseable token
            }
        }

        if (request != null && StringUtils.hasText(request.refreshToken())) {
            refreshTokenService.revoke(request.refreshToken());
        }

        return ResponseEntity.noContent().build();
    }

    /**
     * Return profile and role information for the authenticated user.
     * GET /api/auth/me
     */
    @Operation(
        summary = "Current user",
        description = "Return profile, roles and MFA status of the authenticated user.",
        tags = {"Authentication"}
    )
    @ApiResponse(responseCode = "200", description = "Current user information",
        content = @Content(mediaType = "application/json"))
    @GetMapping("/me")
    public ResponseEntity<?> me(HttpServletRequest http) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof CustomUserDetails userDetails)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(apiI18nService.createLocalizedErrorResponse(
                            "api.unauthorized", HttpStatus.UNAUTHORIZED.value(), http));
        }

        User user = userDetails.getUser();
        Map<String, Object> profile = Map.of(
                "username", user.getUsername(),
                "email", user.getEmail(),
                "name", user.getName() != null ? user.getName() : "",
                "profileImage", user.getProfileImage() != null ? user.getProfileImage() : "",
                "mfaEnabled", Boolean.TRUE.equals(user.getMfaEnabled()),
                "roles", userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList()
        );

        return ResponseEntity.ok(apiI18nService.createSuccessResponse("api.me.success", profile, http));
    }

    /**
     * Issue a new access/refresh token pair and register the access token for revocation.
     */
    private LoginResponse issueTokenPair(String username) {
        JwtService.IssuedToken accessToken = jwtService.issueToken(username, Map.of());
        tokenStore.storeJwt(username, accessToken.jti(), Duration.ofSeconds(jwtService.getTtlSeconds()));
        RefreshTokenService.IssuedRefreshToken refreshToken = refreshTokenService.issue(username);
        return new LoginResponse(accessToken.token(), accessToken.expiresAt(), refreshToken.token(), refreshToken.expiresAt());
    }

    private LoginResponse issueTokenPair(String username, RefreshTokenService.IssuedRefreshToken refreshToken) {
        JwtService.IssuedToken accessToken = jwtService.issueToken(username, Map.of());
        tokenStore.storeJwt(username, accessToken.jti(), Duration.ofSeconds(jwtService.getTtlSeconds()));
        return new LoginResponse(accessToken.token(), accessToken.expiresAt(), refreshToken.token(), refreshToken.expiresAt());
    }

    private void revokeAccessToken(String username, String jti) {
        if (username != null && jti != null) {
            tokenStore.revoke(username, jti);
        }
    }

}
