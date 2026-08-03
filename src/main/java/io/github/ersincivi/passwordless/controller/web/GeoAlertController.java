package io.github.ersincivi.passwordless.controller.web;

import io.github.ersincivi.passwordless.service.GeoAlertService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Geo-alert confirm/deny flow.
 *
 * T5.3: The links in alert emails are GET requests, so they must NOT change
 * state - email scanners and link prefetchers would otherwise auto-confirm or
 * auto-deny (terminating the user's session). GET endpoints therefore render a
 * landing page with the alert details; the actual state change only happens
 * through the CSRF-protected POST form on that page.
 */
@Controller
public class GeoAlertController {

    private static final Logger log = LoggerFactory.getLogger(GeoAlertController.class);

    private final GeoAlertService geoAlertService;

    public GeoAlertController(GeoAlertService geoAlertService) {
        this.geoAlertService = geoAlertService;
    }

    /**
     * Landing page for "Yes, it was me" email links (no state change).
     */
    @GetMapping("/geo-alert/confirm")
    public String confirmLanding(@RequestParam("token") String token, Model model) {
        return landing(token, "confirm", model);
    }

    /**
     * Landing page for "No, it's not me" email links (no state change).
     */
    @GetMapping("/geo-alert/deny")
    public String denyLanding(@RequestParam("token") String token, Model model) {
        return landing(token, "deny", model);
    }

    private String landing(String token, String action, Model model) {
        GeoAlertService.GeoAlertData alertData = geoAlertService.getAlertData(token);
        log.info("[GeoAlert] Landing page ({}) requested for token", action);

        if (alertData == null) {
            model.addAttribute("error", "invalid_or_expired_token");
            log.warn("[GeoAlert] Invalid or expired alert token on landing page");
            return "geo-alert-response";
        }

        model.addAttribute("token", token);
        model.addAttribute("action", action);
        model.addAttribute("currentCountry", alertData.currentCountry());
        model.addAttribute("previousCountry", alertData.previousCountry());
        model.addAttribute("ipAddress", alertData.ipAddress());
        return "geo-alert-landing";
    }

    /**
     * Handle "Yes, it was me" confirmation (POST only).
     */
    @PostMapping("/geo-alert/confirm")
    public String confirmLogin(@RequestParam("token") String token, Model model) {
        GeoAlertService.GeoAlertData alertData = geoAlertService.getAlertData(token);
        log.info("[GeoAlert] Confirm POST received for token: {}", token);

        if (alertData == null) {
            model.addAttribute("error", "invalid_or_expired_token");
            log.warn("[GeoAlert] Invalid or expired confirmation token: {}", token);
            return "geo-alert-response";
        }

        // Mark as confirmed
        geoAlertService.confirmAlert(token);

        model.addAttribute("success", true);
        model.addAttribute("message", "login_confirmed");
        log.info("[GeoAlert] Login confirmed for user '{}' via token: {}", alertData.username(), token);
        return "geo-alert-response";
    }

    /**
     * Handle "No, it's not me" denial (POST only). Immediately terminates the
     * session and offers security recommendations.
     */
    @PostMapping("/geo-alert/deny")
    public String denyLogin(@RequestParam("token") String token, Model model) {
        GeoAlertService.GeoAlertData alertData = geoAlertService.getAlertData(token);
        log.info("[GeoAlert] Deny POST received for token: {}", token);

        if (alertData == null) {
            model.addAttribute("error", "invalid_or_expired_token");
            log.warn("[GeoAlert] Invalid or expired denial token: {}", token);
            return "geo-alert-response";
        }

        // Invalidate the alert token and get the session associated with it
        String sessionId = geoAlertService.denyAlert(token);
        log.info("[GeoAlert] Token is valid. Target session ID to invalidate: '{}'", sessionId);

        if (sessionId != null) {
            log.info("[GeoAlert] Invalidating session, sessionId: {}", sessionId);
            geoAlertService.invalidateSession(sessionId);
        }

        model.addAttribute("denied", true);
        model.addAttribute("message", "login_denied");
        model.addAttribute("username", alertData.username());
        model.addAttribute("showSecurityRecommendations", true);

        return "geo-alert-response";
    }
}
