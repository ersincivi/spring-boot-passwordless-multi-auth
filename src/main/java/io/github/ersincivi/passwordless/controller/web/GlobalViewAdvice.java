package io.github.ersincivi.passwordless.controller.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;
import jakarta.servlet.http.HttpServletRequest;
import io.github.ersincivi.passwordless.config.CspNonceConfig;

@ControllerAdvice
public class GlobalViewAdvice {

    @Value("${app.recaptcha.site-key:}")
    private String recaptchaSiteKey;

    @ModelAttribute("recaptchaSiteKey")
    public String recaptchaSiteKey() {
        return recaptchaSiteKey;
    }
    
    @ModelAttribute("nonce")
    public String nonce(HttpServletRequest request) {
        Object nonce = request.getAttribute(CspNonceConfig.CSP_NONCE_ATTRIBUTE);
        return nonce != null ? nonce.toString() : "";
    }
    
    @ModelAttribute("cspNonce")
    public String cspNonce(HttpServletRequest request) {
        Object nonce = request.getAttribute(CspNonceConfig.CSP_NONCE_ATTRIBUTE);
        return nonce != null ? nonce.toString() : "";
    }
}


