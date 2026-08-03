package io.github.ersincivi.passwordless.controller.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import io.github.ersincivi.passwordless.dto.RegisterForm;
import io.github.ersincivi.passwordless.service.CaptchaService;

import jakarta.servlet.http.HttpServletRequest;

@Controller
public class WebController {

	@Autowired
	private CaptchaService captchaService;

	// Google One Tap client id for the landing page. Comes from the
	// GOOGLE_CLIENT_ID environment variable (see .env.example); the shipped
	// default keeps One Tap disabled until you supply your own.
	@Value("${spring.security.oauth2.client.registration.google.client-id}")
	private String googleClientId;

	@GetMapping("/")
	public String index(Model model) {
		model.addAttribute("googleClientId", googleClientId);
		return "index";
	}

	@GetMapping("/login")
	public String login(@RequestParam(required = false) String username, 
					   @RequestParam(required = false) String captcha,
					   HttpServletRequest request, Model model) {
		
		// Check if CAPTCHA is required for this user/IP
		String identifier = username != null ? username : request.getRemoteAddr();
		boolean captchaRequired = captcha != null && "required".equals(captcha) || 
								  captchaService.isCaptchaRequired(identifier);
		
		model.addAttribute("captchaRequired", captchaRequired);
		
		if (captchaRequired) {
			// Generate CAPTCHA challenge
			String sessionId = request.getSession().getId();
			String clientIP = request.getRemoteAddr();
			CaptchaService.CaptchaChallenge challenge = 
				captchaService.generateCaptcha(sessionId, clientIP);
			model.addAttribute("captchaChallenge", challenge);
		}
		
		return "login";
	}

	@GetMapping("/register")
	public String register(Model model) {
		model.addAttribute("registerForm", new RegisterForm());
		// Initialize error attributes
		model.addAttribute("error", false);
        model.addAttribute("usernameError", false);
        model.addAttribute("emailError", false);
        model.addAttribute("captchaError", false);
		return "register";
	}

}