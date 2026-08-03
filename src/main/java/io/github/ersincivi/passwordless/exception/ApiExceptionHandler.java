package io.github.ersincivi.passwordless.exception;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.BindException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Global exception handler for REST API controllers with internationalization support
 * Provides JSON error responses for API endpoints in multiple languages
 */
@RestControllerAdvice(basePackages = "io.github.ersincivi.passwordless.controller.api")
public class ApiExceptionHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(ApiExceptionHandler.class);
    
    @Autowired
    private MessageSource messageSource;
    
    /**
     * Handle 404 - Not Found
     */
    @ExceptionHandler({NoHandlerFoundException.class, NoResourceFoundException.class})
    public ResponseEntity<Map<String, Object>> handleNotFound(Exception ex, HttpServletRequest request) {
        logger.warn("API 404 Not Found: {} - IP: {}", request.getRequestURI(), request.getRemoteAddr());
        
        Locale locale = resolveLocale(request);
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(createErrorResponse(
                "error.404.title",
                "error.404.message", 
                404, 
                locale
        ));
    }
    
    /**
     * Handle 403 - Access Denied
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleAccessDenied(AccessDeniedException ex, HttpServletRequest request) {
        logger.warn("API 403 Access Denied: {} - IP: {}, User: {}", 
                   request.getRequestURI(), request.getRemoteAddr(), 
                   request.getRemoteUser() != null ? request.getRemoteUser() : "anonymous");
        
        Locale locale = resolveLocale(request);
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(createErrorResponse(
                "error.403.title",
                "error.403.message",
                403,
                locale
        ));
    }
    
    /**
     * Handle authentication exceptions
     */
    @ExceptionHandler({
        BadCredentialsException.class,
        UsernameNotFoundException.class,
        DisabledException.class,
        LockedException.class,
        AuthenticationException.class
    })
    public ResponseEntity<Map<String, Object>> handleAuthException(Exception ex, HttpServletRequest request) {
        logger.warn("API Authentication Exception: {} - IP: {}, Message: {}", 
                   request.getRequestURI(), request.getRemoteAddr(), ex.getMessage());
        
        Locale locale = resolveLocale(request);
        Map<String, Object> response = new HashMap<>();
        response.put("error", "authentication_failed");
        response.put("status", 401);
        response.put("locale", locale.getLanguage());
        response.put("timestamp", java.time.Instant.now());
        
        if (ex instanceof DisabledException) {
            response.put("message", messageSource.getMessage("login.account.disabled", null, 
                    "Account is disabled", locale));
        } else if (ex instanceof LockedException) {
            response.put("message", messageSource.getMessage("login.account.locked", null, 
                    "Account temporarily locked due to multiple failed attempts", locale));
        } else {
            response.put("message", messageSource.getMessage("login.invalid.credentials", null, 
                    "Invalid username or password", locale));
        }
        
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }
    
    /**
     * Handle rate limiting
     */
    @ExceptionHandler(RateLimitExceededException.class)
    public ResponseEntity<Map<String, Object>> handleRateLimit(RateLimitExceededException ex, HttpServletRequest request) {
        logger.warn("API Rate Limit Exceeded: {} - IP: {}, Message: {}", 
                   request.getRequestURI(), request.getRemoteAddr(), ex.getMessage());
        
        Locale locale = resolveLocale(request);
        return ResponseEntity.status(429).body(createErrorResponse(
                "error.429.title",
                "error.429.message",
                429,
                locale
        ));
    }
    
    /**
     * Handle validation exceptions
     */
    @ExceptionHandler({MethodArgumentNotValidException.class, IllegalArgumentException.class})
    public ResponseEntity<Map<String, Object>> handleValidationException(Exception ex, HttpServletRequest request) {
        logger.warn("API Validation Exception: {} - IP: {}, Message: {}", 
                   request.getRequestURI(), request.getRemoteAddr(), ex.getMessage());
        
        Locale locale = resolveLocale(request);
        Map<String, Object> response = createErrorResponse(
                "error.400.title",
                "error.400.message",
                400,
                locale
        );
        
        // Add validation details if available
        if (ex instanceof MethodArgumentNotValidException) {
            MethodArgumentNotValidException validationEx = (MethodArgumentNotValidException) ex;
            Map<String, String> validationErrors = new HashMap<>();
            validationEx.getBindingResult().getFieldErrors().forEach(error -> {
                String localizedMessage = messageSource.getMessage(error.getDefaultMessage(), 
                        error.getArguments(), error.getDefaultMessage(), locale);
                validationErrors.put(error.getField(), localizedMessage);
            });
            response.put("validation_errors", validationErrors);
        }
        
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }
    
    /**
     * Handle database exceptions
     */
    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<Map<String, Object>> handleDataAccessException(DataAccessException ex, HttpServletRequest request) {
        logger.error("API Database Error: {} - IP: {}, Message: {}", 
                    request.getRequestURI(), request.getRemoteAddr(), ex.getMessage(), ex);
        
        Locale locale = resolveLocale(request);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(createErrorResponse(
                "error.500.title",
                "error.500.message",
                500,
                locale
        ));
    }
    
    /**
     * Handle generic exceptions
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGeneric(Exception ex, HttpServletRequest request) {
        logger.error("API Unhandled Exception: {} - IP: {}, Message: {}", 
                    request.getRequestURI(), request.getRemoteAddr(), ex.getMessage(), ex);
        
        Locale locale = resolveLocale(request);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(createErrorResponse(
                "error.500.title",
                "error.500.message",
                500,
                locale
        ));
    }
    
    /**
     * Create standardized error response with internationalization
     */
    private Map<String, Object> createErrorResponse(String titleKey, String messageKey, int status, Locale locale) {
        Map<String, Object> response = new HashMap<>();
        response.put("error", true);
        response.put("status", status);
        response.put("locale", locale.getLanguage());
        response.put("title", messageSource.getMessage(titleKey, null, titleKey, locale));
        response.put("message", messageSource.getMessage(messageKey, null, messageKey, locale));
        response.put("timestamp", java.time.Instant.now());
        return response;
    }
    
    /**
     * Resolve locale from request with fallback mechanisms
     */
    private Locale resolveLocale(HttpServletRequest request) {
        // 1. Check request attribute (set by API locale interceptor)
        Locale apiLocale = (Locale) request.getAttribute("api.locale");
        if (apiLocale != null) {
            return apiLocale;
        }
        
        // 2. Check Accept-Language header
        String acceptLanguage = request.getHeader("Accept-Language");
        if (acceptLanguage != null) {
            try {
                Locale headerLocale = Locale.forLanguageTag(acceptLanguage.split(",")[0].trim());
                if (isSupported(headerLocale)) {
                    return headerLocale;
                }
            } catch (Exception e) {
                logger.debug("Failed to parse Accept-Language header: {}", acceptLanguage);
            }
        }
        
        // 3. Check lang parameter
        String langParam = request.getParameter("lang");
        if (langParam != null) {
            Locale paramLocale = parseLocale(langParam);
            if (isSupported(paramLocale)) {
                return paramLocale;
            }
        }
        
        // 4. Fallback to LocaleContextHolder (Spring's current locale)
        Locale contextLocale = LocaleContextHolder.getLocale();
        if (isSupported(contextLocale)) {
            return contextLocale;
        }
        
        // 5. Final fallback
        return Locale.ENGLISH;
    }
    
    private static Locale parseLocale(String lang) {
        if (lang == null || lang.trim().isEmpty()) {
            return Locale.ENGLISH;
        }
        
        String cleanLang = lang.trim().toLowerCase();
        if (cleanLang.matches("^[a-z]{2}(-[A-Z]{2})?$")) {
            return Locale.forLanguageTag(cleanLang);
        }
        
        return Locale.ENGLISH;
    }
    
    private static boolean isSupported(Locale locale) {
        return io.github.ersincivi.passwordless.config.LocaleConfig.getSupportedLocales()
                .stream()
                .anyMatch(supported -> supported.getLanguage().equals(locale.getLanguage()));
    }
}