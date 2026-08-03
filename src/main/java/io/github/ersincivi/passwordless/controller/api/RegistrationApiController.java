package io.github.ersincivi.passwordless.controller.api;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.ersincivi.passwordless.dto.EmailQueueMessage;
import io.github.ersincivi.passwordless.enums.EmailQueueType;
import io.github.ersincivi.passwordless.service.ApiI18nMessageService;
import io.github.ersincivi.passwordless.service.EmailQueueService;
import io.github.ersincivi.passwordless.service.OTPService;
import io.github.ersincivi.passwordless.service.RecaptchaService;
import io.github.ersincivi.passwordless.service.RegistrationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "User registration with OTP verification")
public class RegistrationApiController {

    private record RegisterRequest(@NotBlank String name, @Email String email) {}

    private record VerifyRequest(@Email String email, @NotBlank String otp) {}

    // private record ResetRequest(@Email String email) {}

    // private record ResetApply(@NotBlank String token, @NotBlank String password) {}

    private final RegistrationService registrationService;
    private final OTPService otpService;
    private final ApiI18nMessageService apiI18nService;
    private final RecaptchaService recaptchaService;
    private final EmailQueueService emailQueueService;
    
    public RegistrationApiController(RegistrationService registrationService, OTPService otpService, ApiI18nMessageService apiI18nService, RecaptchaService recaptchaService, EmailQueueService emailQueueService) {
        this.registrationService = registrationService;
        this.otpService = otpService;
        this.apiI18nService = apiI18nService;
        this.recaptchaService = recaptchaService;
        this.emailQueueService = emailQueueService;
    }

    @Operation(
        summary = "Register User",
        description = "Register a new user with email verification via OTP. " +
                     "Requires reCAPTCHA v3 token in X-Recaptcha-Token header. " +
                     "An OTP will be sent to the provided email for verification.",
        tags = {"Authentication"}
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "OTP sent successfully",
            content = @Content(mediaType = "application/json",
                schema = @Schema(example = "{\"status\": \"otp_sent\"}"))),
        @ApiResponse(responseCode = "400", description = "reCAPTCHA verification failed or invalid input",
            content = @Content(mediaType = "application/json",
                schema = @Schema(example = "{\"error\": \"recaptcha_failed\"}")))
    })
    @PostMapping("/register")
    public ResponseEntity<?> register(
            @RequestBody @Parameter(description = "Registration request with name and email", required = true) RegisterRequest req,
            @Parameter(description = "HTTP request with X-Recaptcha-Token header", required = true) HttpServletRequest request) {
        String token = request.getHeader("X-Recaptcha-Token");
        if (!recaptchaService.verify(token, request.getRemoteAddr())) {
            return ResponseEntity.badRequest().body(Map.of("error", "recaptcha_failed"));
        }
        try {
            registrationService.createPendingUser(req.name(), req.email());
            String otp = otpService.generateOtp(OTPService.Purpose.REGISTER, req.email());
            String subject = apiI18nService.getMessage("email.otp.subject", request);
            emailQueueService.enqueue(new EmailQueueMessage(req.email(), subject, otp, EmailQueueType.VERIFY_OTP, apiI18nService.getCurrentLocale(request)));
        } catch (IllegalArgumentException e) {
            // T3.3: Anti-enumeration - respond uniformly when the email is already
            // registered, without generating or sending an OTP.
        }
        return ResponseEntity.ok(Map.of("status", "otp_sent"));
    }

    @Operation(
        summary = "Verify Registration OTP",
        description = "Verify OTP code to complete user registration. " +
                     "After successful verification, the user account will be activated.",
        tags = {"Authentication"}
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "User verified and activated successfully",
            content = @Content(mediaType = "application/json",
                schema = @Schema(example = "{\"status\": \"verified\"}"))),
        @ApiResponse(responseCode = "400", description = "Invalid or expired OTP",
            content = @Content(mediaType = "application/json",
                schema = @Schema(example = "{\"error\": \"invalid_otp\"}")))
    })
    @PostMapping("/verify-otp")
    public ResponseEntity<?> verify(
            @RequestBody @Parameter(description = "OTP verification request with email and OTP code", required = true) VerifyRequest req,
            @Parameter(description = "HTTP request", required = true) HttpServletRequest request) {
        if (otpService.verifyOtp(OTPService.Purpose.REGISTER, req.email(), req.otp())) {
            registrationService.activateUser(req.email(), request.getRemoteAddr());
            return ResponseEntity.ok(Map.of("status", "verified"));
        }
        return ResponseEntity.badRequest().body(Map.of("error", "invalid_otp"));
    }

}
