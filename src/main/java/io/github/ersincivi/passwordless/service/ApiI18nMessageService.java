package io.github.ersincivi.passwordless.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Locale;
import java.util.Map;

/**
 * Service for API internationalization support
 * Provides centralized language handling for API responses
 */
@Service
public class ApiI18nMessageService {
    
    @Autowired
    private MessageSource messageSource;
    
    @Autowired
    private CookieLocaleResolver localeResolver;
    
    /**
     * Get localized message for API response
     */
    public String getMessage(String key, Object[] args, String defaultMessage, HttpServletRequest request) {
        Locale locale = resolveApiLocale(request);
        return messageSource.getMessage(key, args, defaultMessage, locale);
    }

    /**
     * Get localized message with fallback
     */
    public String getMessage(String key, HttpServletRequest request) {
        return getMessage(key, null, key, request);
    }
    
    /**
     * Create localized API response
     */
    public Map<String, Object> createLocalizedResponse(String messageKey, Object data, HttpServletRequest request) {
        Locale locale = resolveApiLocale(request);
        return Map.of(
            "success", true,
            "message", messageSource.getMessage(messageKey, null, messageKey, locale),
            "locale", locale.getLanguage(),
            "data", data,
            "timestamp", java.time.Instant.now()
        );
    }
    
    /**
     * Create localized error response
     */
    public Map<String, Object> createLocalizedErrorResponse(String messageKey, int status, HttpServletRequest request) {
        Locale locale = resolveApiLocale(request);
        return Map.of(
            "error", true,
            "status", status,
            "message", messageSource.getMessage(messageKey, null, messageKey, locale),
            "locale", locale.getLanguage(),
            "timestamp", java.time.Instant.now()
        );
    }

    /**
     * Create detailed localized error response
     */
    public Map<String, Object> createDetailedLocalizedErrorResponse(String messageKey, Object[] args, int status, HttpServletRequest request) {
        Locale locale = resolveApiLocale(request);
        return Map.of(
            "error", true,
            "status", status,
            "message", messageSource.getMessage(messageKey, args, messageKey, locale),
            "locale", locale.getLanguage(),
            "timestamp", java.time.Instant.now()
        );
    }
    
    /**
     * Create localized success response with custom data
     */
    public Map<String, Object> createSuccessResponse(String messageKey, Object data, HttpServletRequest request) {
        Locale locale = resolveApiLocale(request);
        return Map.of(
            "success", true,
            "message", messageSource.getMessage(messageKey, null, messageKey, locale),
            "locale", locale.getLanguage(),
            "data", data != null ? data : Map.of(),
            "timestamp", java.time.Instant.now()
        );
    }
    
    /**
     * Get current locale for API request
     */
    public Locale getCurrentLocale(HttpServletRequest request) {
        return resolveApiLocale(request);
    }
    
    /**
     * Resolve locale for API request with comprehensive fallback mechanism
     */
    private Locale resolveApiLocale(HttpServletRequest request) {
        // 1. Check request attribute (set by API locale interceptor)
        Locale apiLocale = (Locale) request.getAttribute("api.locale");
        if (apiLocale != null) {
            return apiLocale;
        }
        
        // 2. Check LOCALE cookie (for consistency with web UI)
        try {
            Locale cookieLocale = localeResolver.resolveLocale(request);
            if (cookieLocale != null && isSupported(cookieLocale)) {
                return cookieLocale;
            }
        } catch (Exception e) {
            // Log but continue to next fallback
            org.slf4j.LoggerFactory.getLogger(ApiI18nMessageService.class)
                .debug("Failed to resolve locale from cookie", e);
        }
        
        // 3. Check Accept-Language header
        String acceptLanguage = request.getHeader("Accept-Language");
        if (acceptLanguage != null) {
            try {
                // Parse the first locale from Accept-Language header
                String firstLang = acceptLanguage.split(",")[0].trim();
                if (firstLang.contains(";")) {
                    firstLang = firstLang.split(";")[0].trim();
                }
                Locale headerLocale = Locale.forLanguageTag(firstLang);
                if (isSupported(headerLocale)) {
                    return headerLocale;
                }
            } catch (Exception e) {
                // Log but continue to next fallback
                org.slf4j.LoggerFactory.getLogger(ApiI18nMessageService.class)
                    .debug("Failed to parse Accept-Language header: {}", acceptLanguage);
            }
        }
        
        // 4. Check lang parameter
        String langParam = request.getParameter("lang");
        if (langParam != null) {
            Locale paramLocale = parseLocale(langParam);
            if (isSupported(paramLocale)) {
                return paramLocale;
            }
        }
        
        // 5. Final fallback to English
        return Locale.ENGLISH;
    }
    
    /**
     * Parse and sanitize locale string
     */
    private static Locale parseLocale(String lang) {
        if (lang == null || lang.trim().isEmpty()) {
            return Locale.ENGLISH;
        }
        
        // Security: sanitize input to prevent injection
        String cleanLang = lang.trim().toLowerCase();
        if (cleanLang.matches("^[a-z]{2}(-[A-Z]{2})?$")) {
            return Locale.forLanguageTag(cleanLang);
        }
        
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