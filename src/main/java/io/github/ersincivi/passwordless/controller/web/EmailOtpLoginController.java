package io.github.ersincivi.passwordless.controller.web;

import io.github.ersincivi.passwordless.domain.User;
import io.github.ersincivi.passwordless.dto.EmailQueueMessage;
import io.github.ersincivi.passwordless.enums.EmailQueueType;
import io.github.ersincivi.passwordless.security.PreMfaAuthenticationToken;
import io.github.ersincivi.passwordless.service.ApiI18nMessageService;
import io.github.ersincivi.passwordless.service.EmailQueueService;
import io.github.ersincivi.passwordless.service.LastLoginInfoService;
import io.github.ersincivi.passwordless.service.OTPService;
import io.github.ersincivi.passwordless.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Locale;
import java.util.Map;

@RestController
@RequestMapping("/auth/email-otp")
public class EmailOtpLoginController {

    private static final Logger log = LoggerFactory.getLogger(EmailOtpLoginController.class);

    private final OTPService otpService;
    private final EmailQueueService emailQueueService;
    private final ApiI18nMessageService apiMessageService;
    private final UserDetailsService userDetailsService;
    private final LastLoginInfoService lastLoginInfoService;
    private final UserService userService;

    public EmailOtpLoginController(OTPService otpService, EmailQueueService emailQueueService,
            ApiI18nMessageService apiMessageService, UserDetailsService userDetailsService, 
            LastLoginInfoService lastLoginInfoService, UserService userService) {
        this.otpService = otpService;
        this.emailQueueService = emailQueueService;
        this.apiMessageService = apiMessageService;
        this.userDetailsService = userDetailsService;
        this.lastLoginInfoService = lastLoginInfoService;
        this.userService = userService;
    }

    /**
     * Send OTP to email for passwordless login
     */
    @PostMapping("/send")
    public ResponseEntity<Map<String, Object>> sendEmailOtp(@RequestBody Map<String, String> payload,
            HttpServletRequest request) {

        try {
            String email = payload.get("email");

            if (email == null || email.isBlank()) {
                log.warn("Email OTP Login: Missing email in request");
                return ResponseEntity.badRequest()
                        .body(apiMessageService.createLocalizedErrorResponse(
                                "register.email.required",
                                HttpStatus.BAD_REQUEST.value(),
                                request
                        ));
            }
            // Validate email format
            if (!email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")) {
                log.warn("Email OTP Login: Invalid email format: {}", email);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(apiMessageService.createLocalizedErrorResponse(
                                "register.email.invalid",
                                HttpStatus.BAD_REQUEST.value(), request));
            }

            // T3.3: Anti-enumeration - respond uniformly whether or not the account exists.
            // Only generate and send the code when the account actually exists.
            boolean userExists = userService.getFullUserByEmail(email).isPresent();
            if (!userExists) {
                log.info("Email OTP Login: requested for unknown email (responding uniformly)");
                return ResponseEntity.ok().body(
                        apiMessageService.createSuccessResponse("login.email.otp.code.sent",
                                Map.of("email", email), request));
            }

            // Generate OTP
            String otp = otpService.generateOtp(OTPService.Purpose.LOGIN, email);
            log.info("Email OTP Login: Generated OTP for email: {}", email);
            // Get localized subject for email
            String subject = apiMessageService.getMessage("email.otp.login.subject", request);

            // Get current locale for email
            Locale locale = apiMessageService.getCurrentLocale(request);
            // Queue email with OTP
            EmailQueueMessage emailMessage = new EmailQueueMessage(email, subject, otp,
                    EmailQueueType.VERIFY_OTP, locale);
            emailQueueService.enqueue(emailMessage);
            log.info("Email OTP Login: OTP email queued for {}", email);

            return ResponseEntity.ok().body(
                    apiMessageService.createSuccessResponse("login.email.otp.code.sent",
                            Map.of("email", email), request));
        } catch (Exception e) {
            log.error("Email OTP Login: Error sending OTP", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(apiMessageService.createLocalizedErrorResponse(
                            "login.email.error.send.failed",
                            HttpStatus.INTERNAL_SERVER_ERROR.value(), request));
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<Map<String, Object>> verifyEmailOtp(@RequestBody Map<String, String> payload,
            HttpServletRequest request) {

        try {
            String email = payload.get("email");
            String otp = payload.get("otp");

            if (email == null || email.isBlank()) {
                log.warn("Email OTP Verify: Missing email in request");
                return ResponseEntity.badRequest()
                        .body(apiMessageService.createLocalizedErrorResponse(
                                "register.email.required",
                                HttpStatus.BAD_REQUEST.value(),
                                request));
            }

            if (otp == null || otp.isBlank()) {
                log.warn("Email OTP Verify: Missing OTP in request");
                return ResponseEntity.badRequest()
                        .body(apiMessageService.createLocalizedErrorResponse(
                                "login.email.otp.verification.code",
                                HttpStatus.BAD_REQUEST.value(), request));
            }

            // Verify OTP
            if (!otpService.verifyOtp(OTPService.Purpose.LOGIN, email, otp)) {
                log.warn("Email OTP Verify: Invalid OTP for email: {}", email);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(apiMessageService.createLocalizedErrorResponse(
                                "login.email.error.invalid.code",
                                HttpStatus.UNAUTHORIZED.value(),
                                request));
            }

            // Find user by email using service layer (not repository directly)
            User user = userService.getFullUserByEmail(email).orElse(null);

            if (user == null) {
                log.warn("Email OTP Verify: User not found for email: {}", email);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(apiMessageService.createLocalizedErrorResponse(
                                "login.email.error.user.not.found",
                                HttpStatus.UNAUTHORIZED.value(),
                                request));
            }

            if (!user.isEnabled()) {
                log.warn("Email OTP Verify: User account disabled for email: {}", email);
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(apiMessageService.createLocalizedErrorResponse(
                                "login.email.error.account.disabled",
                                HttpStatus.FORBIDDEN.value(),
                                request));
            }

            // Load proper UserDetails object with all authorities
            UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());

            // Check if TOTP is enabled for this user
            boolean totpEnabled = userService.findUserMfaByUsername(user.getUsername())
                    .map(mfa -> Boolean.TRUE.equals(mfa.getMfaEnabled()))
                    .orElse(false);

            HttpSession session = request.getSession(true);

            if (totpEnabled) {
                // TOTP is required - create pending authentication
                log.info("Email OTP Verify: TOTP required for user {}, creating pending authentication", user.getUsername());
                
                // Store username for TotpFilter to identify user
                session.setAttribute("PENDING_USERNAME", user.getUsername());
                session.setAttribute("PENDING_AUTH_TIME", System.currentTimeMillis());
                
                // T3.1: Create restricted pre-MFA authentication (authenticated, no authorities).
                // TotpWebController upgrades it to a full authentication after TOTP success.
                UsernamePasswordAuthenticationToken tempAuth = new PreMfaAuthenticationToken(userDetails);
                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                securityContext.setAuthentication(tempAuth);
                SecurityContextHolder.setContext(securityContext);
                
                // Save temporary security context to session
                session.setAttribute(
                        HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                        securityContext);
                
                log.info("Email OTP Verify: Pending authentication created for TOTP verification");
                
                return ResponseEntity.ok()
                        .body(apiMessageService.createSuccessResponse(
                                "login.otp.verified.totp.required",
                                Map.of(
                                        "redirectUrl", "/totp",
                                        "username", user.getName(),
                                        "email", user.getEmail(),
                                        "totpRequired", true),
                                request));
            } else {
                // TOTP not required - complete authentication immediately
                log.info("Email OTP Verify: TOTP not required for user {}, completing authentication", user.getUsername());
                
                // Create full authentication
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());

                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                securityContext.setAuthentication(authentication);
                SecurityContextHolder.setContext(securityContext);

                // Save security context to session
                session.setAttribute(
                        HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                        securityContext);

                return ResponseEntity.ok()
                        .body(apiMessageService.createSuccessResponse(
                                "login.success",
                                Map.of(
                                        "redirectUrl", "/",
                                        "username", user.getName(),
                                        "email", user.getEmail()),
                                request));
            }

        } catch (Exception e) {
            log.error("Email OTP Verify: Error verifying OTP", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(apiMessageService.createLocalizedErrorResponse(
                            "login.email.error.verification.failed",
                            HttpStatus.INTERNAL_SERVER_ERROR.value(),
                            request));
        }
    }
}
