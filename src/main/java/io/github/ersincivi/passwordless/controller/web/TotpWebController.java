package io.github.ersincivi.passwordless.controller.web;

import io.github.ersincivi.passwordless.dto.projection.UserMfaProjection;
import io.github.ersincivi.passwordless.service.UserService;
import io.github.ersincivi.passwordless.service.TotpService;
import io.github.ersincivi.passwordless.security.TotpFilter;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;

@Controller
public class TotpWebController {

    private final TotpService totpService;
    private final UserService userService;
    private final UserDetailsService userDetailsService;

    public TotpWebController(TotpService totpService, UserService userService, UserDetailsService userDetailsService) {
        this.totpService = totpService;
        this.userService = userService;
        this.userDetailsService = userDetailsService;
    }

    @GetMapping("/totp")
    public String totpPage(Principal principal, Model model) {
        String username = principal != null ? principal.getName() : null;
        model.addAttribute("username", username != null ? username : "");
        return "totp";
    }
    
    /**
     * Cancel TOTP verification and clear pending authentication
     */
    @GetMapping("/totp/cancel")
    public String cancelTotpVerification(HttpSession session) {
        // Clear pending authentication session attributes
        session.removeAttribute("PENDING_USERNAME");
        session.removeAttribute("PENDING_AUTH_TIME");
        session.removeAttribute(TotpFilter.SESSION_TOTP_OK);
        
        // Clear security context to ensure clean logout
        SecurityContextHolder.clearContext();
        
        // Invalidate session to ensure all attributes are cleared
        session.invalidate();
        
        return "redirect:/login";
    }

    @PostMapping("/totp")
    public String verify(Principal principal, @RequestParam("code") String code, 
                        HttpSession session, HttpServletRequest request, Model model) {
        String username = principal != null ? principal.getName() : null;
        
        // If no active principal, try to get from PENDING_USERNAME (for pending TOTP auth)
        if (username == null) {
            Object pendingUsername = session.getAttribute("PENDING_USERNAME");
            if (pendingUsername instanceof String s) {
                username = s;
            } else {
                return "redirect:/login";
            }
        }

        UserMfaProjection userMfa = userService.findUserMfaByUsername(username).orElse(null);
        if (userMfa == null || userMfa.getMfaSecret() == null || !Boolean.TRUE.equals(userMfa.getMfaEnabled())) {
            model.addAttribute("error", "totp_not_enabled");
            return "totp";
        }

        String userAgent = request.getHeader("User-Agent");
        
        TotpService.TotpVerificationResult result;
        try {
            result = totpService.verifyCode(userMfa.getUsername(), userMfa.getMfaSecret(), code, request.getRemoteAddr(), userAgent);
        } catch (Exception e) {
            model.addAttribute("error", "verification_error");
            return "totp";
        }
        
        if (!result.isValid()) {
            model.addAttribute("error", "invalid_code");
            return "totp";
        }

        session.setAttribute(TotpFilter.SESSION_TOTP_OK, Boolean.TRUE);
        
        // If this was a pending authentication (from form login or OAuth), complete it
        Object pendingUsernameObj = session.getAttribute("PENDING_USERNAME");
        if (pendingUsernameObj != null && pendingUsernameObj.equals(username)) {
            // Complete the authentication by creating proper security context
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            UsernamePasswordAuthenticationToken authToken = 
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authToken);
            
            // Save the security context to session
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, 
                                SecurityContextHolder.getContext());
            
            // Clear pending authentication
            session.removeAttribute("PENDING_USERNAME");
            session.removeAttribute("PENDING_AUTH_TIME");
        }
        
        return "redirect:/";
    }
    
    /**
     * Verify TOTP backup code
     */
    @PostMapping("/totp/backup")
    public String verifyBackupCode(Principal principal, @RequestParam("backupCode") String backupCode,
                                   HttpSession session, HttpServletRequest request, Model model) {
        String username = principal != null ? principal.getName() : null;
        
        // If no active principal, try to get from PENDING_USERNAME (for pending TOTP auth)
        if (username == null) {
            Object pendingUsername = session.getAttribute("PENDING_USERNAME");
            if (pendingUsername instanceof String s) {
                username = s;
            } else {
                return "redirect:/login";
            }
        }
        
        // Verify TOTP is enabled for this user
        UserMfaProjection userMfa = userService.findUserMfaByUsername(username).orElse(null);
        if (userMfa == null || !Boolean.TRUE.equals(userMfa.getMfaEnabled())) {
            model.addAttribute("error", "totp_not_enabled");
            return "totp";
        }
        String userAgent = request.getHeader("User-Agent");
        
        TotpService.TotpVerificationResult result;
        try {
            result = totpService.verifyBackupCode(username, backupCode, request.getRemoteAddr(), userAgent);
        } catch (Exception e) {
            model.addAttribute("error", "verification_error");
            return "totp";
        }
        
        if (!result.isValid()) {
            model.addAttribute("error", "backup_code_invalid");
            return "totp";
        }
        
        // Backup code verified successfully, set session flag
        session.setAttribute(TotpFilter.SESSION_TOTP_OK, Boolean.TRUE);
        
        // If this was a pending authentication (from form login or OAuth), complete it
        Object pendingUsernameObj = session.getAttribute("PENDING_USERNAME");
        if (pendingUsernameObj != null && pendingUsernameObj.equals(username)) {
            // Complete the authentication by creating proper security context
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            UsernamePasswordAuthenticationToken authToken = 
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authToken);
            
            // Save the security context to session
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, 
                                SecurityContextHolder.getContext());
            
            // Clear pending authentication
            session.removeAttribute("PENDING_USERNAME");
            session.removeAttribute("PENDING_AUTH_TIME");
        }
        
        return "redirect:/";
    }

}


