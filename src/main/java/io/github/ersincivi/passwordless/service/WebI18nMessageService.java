package io.github.ersincivi.passwordless.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Locale;

/**
 * Service for Web UI internationalization support
 * Provides centralized language handling for web controllers and filters
 * Follows the project specification for i18n key synchronization across en, de, and tr locales
 */
@Service
public class WebI18nMessageService {
    
    @Autowired
    private MessageSource messageSource;
    
    @Autowired
    @Qualifier("localeResolver")
    private CookieLocaleResolver webLocaleResolver;
    
    /**
     * Get localized message for web UI
     * Uses web locale resolver (cookie-based) for consistent user experience
     */
    public String getMessage(String key, Object[] args, String defaultMessage, HttpServletRequest request) {
        Locale locale = resolveWebLocale(request);
        return messageSource.getMessage(key, args, defaultMessage, locale);
    }
    
    /**
     * Get localized message with fallback to key as default
     */
    public String getMessage(String key, HttpServletRequest request) {
        return getMessage(key, null, key, request);
    }
    
    /**
     * Get localized message with single argument
     */
    public String getMessage(String key, Object arg, HttpServletRequest request) {
        return getMessage(key, new Object[]{arg}, key, request);
    }
    
    /**
     * Get localized message for email subjects (commonly used in web flows)
     * Uses English as default for email consistency across locales
     */
    public String getEmailSubject(String key, String defaultSubject, HttpServletRequest request) {
        // For emails, we can use the user's preferred locale or fall back to English
        Locale locale = resolveWebLocale(request);
        return messageSource.getMessage(key, null, defaultSubject, locale);
    }
    
    /**
     * Get localized message for email subjects with fallback to English
     * This ensures email subjects are always readable
     */
    public String getEmailSubject(String key, String defaultSubject) {
        // Default to English for email subjects when no request context
        return messageSource.getMessage(key, null, defaultSubject, Locale.ENGLISH);
    }
    
    /**
     * Get current web locale for the request
     */
    public Locale getCurrentLocale(HttpServletRequest request) {
        return resolveWebLocale(request);
    }
    
    /**
     * Resolve locale for web request using the configured web locale resolver
     * This uses cookie-based locale resolution for persistent user preferences
     */
    private Locale resolveWebLocale(HttpServletRequest request) {
        if (request == null) {
            return Locale.ENGLISH;
        }
        
        try {
            Locale resolvedLocale = webLocaleResolver.resolveLocale(request);
            if (resolvedLocale != null && isSupported(resolvedLocale)) {
                return resolvedLocale;
            }
        } catch (Exception e) {
            // Log but continue to fallback
            org.slf4j.LoggerFactory.getLogger(WebI18nMessageService.class)
                .debug("Failed to resolve web locale from request", e);
        }
        
        // Fallback to English
        return Locale.ENGLISH;
    }
    
    /**
     * Check if locale is supported by the application
     */
    private static boolean isSupported(Locale locale) {
        return io.github.ersincivi.passwordless.config.LocaleConfig.getSupportedLocales()
                .stream()
                .anyMatch(supported -> supported.getLanguage().equals(locale.getLanguage()));
    }
}