package io.github.ersincivi.passwordless.controller.web;

import io.github.ersincivi.passwordless.dto.EmailQueueMessage;
import io.github.ersincivi.passwordless.dto.RegisterForm;
import io.github.ersincivi.passwordless.service.EmailQueueService;
import io.github.ersincivi.passwordless.service.OTPService;
import io.github.ersincivi.passwordless.service.RecaptchaService;
import io.github.ersincivi.passwordless.service.RegistrationService;
import io.github.ersincivi.passwordless.service.WebI18nMessageService;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.validation.BindingResult;

import io.github.ersincivi.passwordless.enums.EmailQueueType;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

@Controller
public class WebRegistrationController {

    private record OtpForm(@Email String email, @NotBlank String otp) {}

    @Autowired
    private WebI18nMessageService webI18nMessageService;

    private final RegistrationService registrationService;
    private final OTPService otpService;
    private final RecaptchaService recaptchaService;
    private final EmailQueueService emailQueueService;
    private final UserDetailsService userDetailsService;

    public WebRegistrationController(RegistrationService registrationService, OTPService otpService, 
            RecaptchaService recaptchaService, EmailQueueService emailQueueService,
            UserDetailsService userDetailsService) {
        this.registrationService = registrationService;
        this.otpService = otpService;
        this.recaptchaService = recaptchaService;
        this.emailQueueService = emailQueueService;
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/register")
    public String register(@Valid @ModelAttribute("registerForm") RegisterForm registerForm, BindingResult bindingResult,
            @RequestParam(name = "g-recaptcha-response", required = false) String recaptchaToken,
            HttpServletRequest request, Model model) {

        // Add the form object to the model so it can be used in the view
        model.addAttribute("registerForm", registerForm);

        // Initialize error attributes
        model.addAttribute("error", false);
        model.addAttribute("emailError", false);
        model.addAttribute("captchaError", false);

        // Check for validation errors
        if (bindingResult.hasErrors()) {
            // Return to the registration page with validation errors
            return "register";
        }

        if (!recaptchaService.verify(recaptchaToken, request.getRemoteAddr())) {
            model.addAttribute("captchaError", true);
            return "register";
        }

        try {
            registrationService.createPendingUser(registerForm.getName(), registerForm.getEmail());
            String otp = otpService.generateOtp(OTPService.Purpose.REGISTER, registerForm.getEmail());
            String subject = webI18nMessageService.getEmailSubject("email.otp.subject", "Your OTP Code", request);
            emailQueueService.enqueue(new EmailQueueMessage(registerForm.getEmail(), subject, otp, EmailQueueType.VERIFY_OTP, webI18nMessageService.getCurrentLocale(request)));
            
            model.addAttribute("email", registerForm.getEmail());
            model.addAttribute("name", registerForm.getName());
            return "verify-otp";

        } catch (IllegalArgumentException e) {
            if (e.getMessage() != null && e.getMessage().contains("Email already exists")) {
                // T3.3: Anti-enumeration - render the same verification page without
                // generating or sending an OTP, so account existence is not revealed.
                model.addAttribute("email", registerForm.getEmail());
                model.addAttribute("name", registerForm.getName());
                return "verify-otp";
            }
            // For any other IllegalArgumentException, set a general error
            model.addAttribute("error", true);
            return "register";
        } catch (Exception e) {
            // For any other exception, set a general error
            model.addAttribute("error", true);
            return "register";
        }
    }

    @PostMapping("/verify-otp")
    public String verifyOtp(@ModelAttribute OtpForm form, HttpServletRequest request, HttpSession session, Model model) {
        if (otpService.verifyOtp(OTPService.Purpose.REGISTER, form.email(), form.otp())) {
            registrationService.activateUser(form.email(), request.getRemoteAddr());
            
            // Auto-login the user after successful registration verification
            try {
                // Load user details
                UserDetails userDetails = userDetailsService.loadUserByUsername(form.email());
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                
                // Set authentication in security context
                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                securityContext.setAuthentication(authentication);
                SecurityContextHolder.setContext(securityContext);
                
                // Save security context to session
                session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, securityContext);
                
                // Redirect to home page after successful auto-login
                return "redirect:/";
            } catch (Exception e) {
                // If auto-login fails, redirect to login page with verified parameter
                return "redirect:/login?verified";
            }
        }
        model.addAttribute("email", form.email());
        model.addAttribute("error", true);
        return "verify-otp";
    }

}
