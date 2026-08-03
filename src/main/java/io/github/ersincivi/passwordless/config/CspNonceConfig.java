package io.github.ersincivi.passwordless.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.HandlerInterceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Configuration for Content Security Policy (CSP) nonce generation
 * Provides enhanced security by generating unique nonces for inline scripts
 */
@Configuration
public class CspNonceConfig implements WebMvcConfigurer {

    public static final String CSP_NONCE_ATTRIBUTE = "cspNonce";
    private static final SecureRandom secureRandom = new SecureRandom();

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new CspNonceInterceptor());
    }

    /**
     * Interceptor to generate unique CSP nonce for each request
     */
    public static class CspNonceInterceptor implements HandlerInterceptor {
        
        @Override
        public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
            // Generate a unique nonce for this request
            String nonce = generateNonce();
            
            // Store nonce in request attributes for template access
            request.setAttribute(CSP_NONCE_ATTRIBUTE, nonce);
            
            // Add nonce to CSP header if it's a page request (not API)
            String requestUri = request.getRequestURI();
            if (!requestUri.startsWith("/api/") && !requestUri.startsWith("/actuator/")) {
                String cspPolicy = buildCspPolicyWithNonce(nonce);
                response.setHeader("Content-Security-Policy", cspPolicy);
            }
            
            return true;
        }
        
        /**
         * Generate a cryptographically secure random nonce
         */
        private String generateNonce() {
            byte[] nonceBytes = new byte[16];
            secureRandom.nextBytes(nonceBytes);
            return Base64.getEncoder().encodeToString(nonceBytes);
        }
        
        /**
         * Build CSP policy with nonce for enhanced security
         */
        private String buildCspPolicyWithNonce(String nonce) {
            return String.format(
                "default-src 'self'; " +
                "script-src 'self' 'nonce-%s'; " +
                "style-src 'self' 'unsafe-inline'; " +
                "object-src 'none'; " +
                "frame-ancestors 'none'; " +
                "base-uri 'self'; " +
                "form-action 'self'; " +
                "font-src 'self' data:; " +
                "img-src 'self' data: https:; " +
                "connect-src 'self'; " +
                "media-src 'none'; " +
                "worker-src 'none'; " +
                "manifest-src 'self'; " +
                "upgrade-insecure-requests",
                nonce
            );
        }
    }
}