package io.github.ersincivi.passwordless.service;

import io.github.ersincivi.passwordless.domain.User;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

import java.util.Locale;
import java.util.Map;

/**
 * T4.2: Audit parity for API login flows.
 *
 * Web logins run through AuthenticationSuccessHandler / AuthenticationFailureHandler,
 * which clear lockout counters, write audit events and send geo-change alerts.
 * API (mobile) logins bypass those handlers, so this service applies the same
 * post-login processing to the API endpoints in AuthApiController.
 */
@Service
public class ApiLoginEventService {

    private final AccountLockoutService accountLockoutService;
    private final SecurityAuditService securityAuditService;
    private final GeoIpService geoIpService;
    private final GeoAlertService geoAlertService;

    public ApiLoginEventService(AccountLockoutService accountLockoutService,
                                SecurityAuditService securityAuditService,
                                GeoIpService geoIpService,
                                GeoAlertService geoAlertService) {
        this.accountLockoutService = accountLockoutService;
        this.securityAuditService = securityAuditService;
        this.geoIpService = geoIpService;
        this.geoAlertService = geoAlertService;
    }

    /**
     * Post-login processing for successful API authentication, mirroring the web
     * AuthenticationSuccessHandler: lockout reset, LOGIN_SUCCESS audit event and
     * informational geo-change alert email.
     */
    public void onLoginSuccess(User user, String loginMethod, HttpServletRequest request, Locale locale) {
        String username = user.getUsername();
        String ip = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        accountLockoutService.clearFailedAttempts(username);

        securityAuditService.logAuthenticationEvent(
                username, "LOGIN_SUCCESS", "SUCCESS", ip, userAgent,
                securityAuditService.extractRequestInfo(request));

        // Geo alert on country change (informational only, no verification required)
        if (geoIpService.isAvailable() && user.getEmail() != null) {
            String currentCountry = geoIpService.lookupCountryIso(ip).orElse(null);
            String lastLoginIp = user.getLastLoginIp();
            String previousCountry = lastLoginIp != null
                    ? geoIpService.lookupCountryIso(lastLoginIp).orElse(null)
                    : null;

            if (currentCountry != null && previousCountry != null && !currentCountry.equals(previousCountry)) {
                // No web session exists for API logins; sessionId stays null so a
                // "deny" action simply cannot invalidate a (non-existent) session.
                geoAlertService.sendGeoAlert(
                        user.getEmail(), username, null,
                        currentCountry, previousCountry, ip,
                        locale != null ? locale : Locale.ENGLISH);
            }
        }
    }

    /**
     * Failed API login processing, mirroring the web AuthenticationFailureHandler:
     * increments the lockout counter (when the account is known) and writes a
     * LOGIN_FAILURE audit event.
     */
    public void onLoginFailure(String username, String reason, HttpServletRequest request) {
        if (username != null && !username.isBlank()) {
            accountLockoutService.recordFailedAttempt(username);
        }
        securityAuditService.logAuthenticationEvent(
                username != null && !username.isBlank() ? username : "unknown",
                "LOGIN_FAILURE", "FAILURE",
                request.getRemoteAddr(), request.getHeader("User-Agent"),
                Map.of("reason", reason, "channel", "api"));
    }

    /**
     * Whether the account is currently locked out (mirrors AccountLockoutFilter
     * on the web chain).
     */
    public boolean isAccountLocked(String username) {
        return accountLockoutService.isAccountLocked(username);
    }
}
