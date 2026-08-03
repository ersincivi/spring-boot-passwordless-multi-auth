package io.github.ersincivi.passwordless.controller.web;

import io.github.ersincivi.passwordless.dto.EmailQueueMessage;
import io.github.ersincivi.passwordless.enums.EmailQueueType;
import io.github.ersincivi.passwordless.service.ApiI18nMessageService;
import io.github.ersincivi.passwordless.service.EmailQueueService;
import io.github.ersincivi.passwordless.service.MagicLinkService;
import io.github.ersincivi.passwordless.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.Locale;
import java.util.Map;

/**
 * Web controller for MagicLink passwordless authentication — one-click login
 * links as an alternative to e-mail OTP.
 *
 * <p>This controller owns the application side only: issuing a link via
 * {@code POST /email-magiclink/send}. Consuming the link is security-layer
 * work and lives in {@code MagicLinkAuthenticationFilter}, which intercepts
 * {@code GET /auth/verify} and delegates to {@code MagicLinkAuthenticationProvider}
 * through the shared {@code AuthenticationManager}.
 *
 * <p>Routing verification through the filter chain is what keeps MagicLink on
 * the same path as OAuth2 and OIDC: the success and failure handlers fire, so
 * GeoIP anomaly detection, account lockout and audit logging run for every
 * authentication method, 2FA is applied centrally by {@code TotpFilter}, and
 * nothing here writes to the {@code SecurityContext} by hand.
 */
@Controller
@RequestMapping("/auth")
public class MagicLinkWebController {

    private static final Logger log = LoggerFactory.getLogger(MagicLinkWebController.class);

    private final MagicLinkService magicLinkService;
    private final EmailQueueService emailQueueService;
    private final ApiI18nMessageService apiMessageService;
    private final UserService userService;

    @Value("${app.base-url}")
    private String baseUrl;

    public MagicLinkWebController(MagicLinkService magicLinkService,
                                 EmailQueueService emailQueueService,
                                 ApiI18nMessageService apiMessageService,
                                 UserService userService) {
        this.magicLinkService = magicLinkService;
        this.emailQueueService = emailQueueService;
        this.apiMessageService = apiMessageService;
        this.userService = userService;
    }

    /**
     * Send MagicLink to email for passwordless login
     * POST /auth/email-magiclink/send
     */
    @PostMapping("/email-magiclink/send")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> sendMagicLink(@RequestBody Map<String, String> payload,
                                                              HttpServletRequest request) {
        try {
            String email = payload.get("email");

            if (email == null || email.isBlank()) {
                log.warn("MagicLink: Missing email in request");
                return ResponseEntity.badRequest()
                        .body(apiMessageService.createLocalizedErrorResponse(
                                "register.email.required",
                                HttpStatus.BAD_REQUEST.value(),
                                request
                        ));
            }

            // Validate email format
            if (!email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")) {
                log.warn("MagicLink: Invalid email format: {}", email);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(apiMessageService.createLocalizedErrorResponse(
                                "register.email.invalid",
                                HttpStatus.BAD_REQUEST.value(), request));
            }

            // T3.3: Anti-enumeration - respond uniformly whether or not the account exists.
            // Only generate and send the link when the account actually exists.
            boolean userExists = userService.getFullUserByEmail(email).isPresent();
            if (!userExists) {
                log.info("MagicLink: requested for unknown email (responding uniformly)");
                return ResponseEntity.ok().body(
                        apiMessageService.createSuccessResponse(
                                "login.magiclink.sent",
                                Map.of(
                                        "email", email,
                                        "ttlSeconds", magicLinkService.getWebTtlSeconds()
                                ),
                                request
                        ));
            }

            // Generate MagicLink token (UUID v7)
            String token = magicLinkService.generateWebToken(email);
            
            // Build MagicLink URL
            String magicLinkUrl = baseUrl + "/auth/verify?token=" + token;
            
            log.info("MagicLink: Generated for email: {} - URL: {}", email, magicLinkUrl);

            // Get localized subject for email
            String subject = apiMessageService.getMessage("email.magiclink.subject", request);

            // Get current locale for email
            Locale locale = apiMessageService.getCurrentLocale(request);

            // Queue email with MagicLink
            EmailQueueMessage emailMessage = new EmailQueueMessage(
                    email, 
                    subject, 
                    magicLinkUrl,
                    EmailQueueType.MAGICLINK_WEB, 
                    locale
            );
            emailQueueService.enqueue(emailMessage);
            
            log.info("MagicLink: Email queued for {}", email);

            return ResponseEntity.ok().body(
                    apiMessageService.createSuccessResponse(
                            "login.magiclink.sent",
                            Map.of(
                                    "email", email,
                                    "ttlSeconds", magicLinkService.getWebTtlSeconds()
                            ),
                            request
                    ));
        } catch (Exception e) {
            log.error("MagicLink: Error sending MagicLink", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(apiMessageService.createLocalizedErrorResponse(
                            "login.magiclink.error.send.failed",
                            HttpStatus.INTERNAL_SERVER_ERROR.value(), request));
        }
    }

}
