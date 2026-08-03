package io.github.ersincivi.passwordless.exception;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.validation.BindException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.LocaleResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Locale;

/**
 * Global exception handler for web controllers with internationalization support
 * Leverages Spring Boot's automatic error page resolution with existing localized templates
 */
@ControllerAdvice(basePackages = "io.github.ersincivi.passwordless.controller.web")
public class WebExceptionHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(WebExceptionHandler.class);
    
    @Autowired
    private MessageSource messageSource;
    
    @Autowired
    private LocaleResolver localeResolver;
    
    /**
     * Handle 404 - Page Not Found
     * Spring Boot will automatically serve /error/404.html with i18n support
     */
    @ExceptionHandler({NoHandlerFoundException.class, NoResourceFoundException.class})
    public ModelAndView handleNotFound(Exception ex, HttpServletRequest request) {
        logger.warn("Web 404 Not Found: {} - IP: {}", request.getRequestURI(), request.getRemoteAddr());
        
        ModelAndView mav = new ModelAndView("error/404");
        mav.setStatus(HttpStatus.NOT_FOUND);
        return mav;
    }
    
    /**
     * Handle 403 - Access Denied
     * Spring Boot will automatically serve /error/403.html with i18n support
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ModelAndView handleAccessDenied(AccessDeniedException ex, HttpServletRequest request) {
        logger.warn("Web 403 Access Denied: {} - IP: {}, User: {}", 
                   request.getRequestURI(), request.getRemoteAddr(), 
                   request.getRemoteUser() != null ? request.getRemoteUser() : "anonymous");
        
        ModelAndView mav = new ModelAndView("error/403");
        mav.setStatus(HttpStatus.FORBIDDEN);
        return mav;
    }
    
    /**
     * Handle authentication exceptions
     * Store localized error message in session for login page display
     */
    @ExceptionHandler({
        BadCredentialsException.class,
        UsernameNotFoundException.class,
        DisabledException.class,
        LockedException.class,
        AuthenticationException.class
    })
    public ModelAndView handleAuthException(Exception ex, HttpServletRequest request) {
        logger.warn("Web Authentication Exception: {} - IP: {}, Message: {}", 
                   request.getRequestURI(), request.getRemoteAddr(), ex.getMessage());
        
        // Resolve locale for error message
        Locale locale = resolveLocale(request);
        String errorMessage;
        
        if (ex instanceof DisabledException) {
            errorMessage = messageSource.getMessage("login.account.disabled", null, 
                    "Account is disabled", locale);
        } else if (ex instanceof LockedException) {
            errorMessage = messageSource.getMessage("login.account.locked", null, 
                    "Account temporarily locked due to multiple failed attempts", locale);
        } else {
            errorMessage = messageSource.getMessage("login.invalid.credentials", null, 
                    "Invalid username or password", locale);
        }
        
        // Store error message in session for display on login page
        request.getSession().setAttribute("errorMessage", errorMessage);
        
        ModelAndView mav = new ModelAndView("redirect:/login?error");
        return mav;
    }
    
    /**
     * Handle rate limiting
     * Spring Boot will automatically serve /error/429.html with i18n support
     */
    @ExceptionHandler(RateLimitExceededException.class)
    public ModelAndView handleRateLimit(RateLimitExceededException ex, HttpServletRequest request) {
        logger.warn("Web Rate Limit Exceeded: {} - IP: {}, Message: {}", 
                   request.getRequestURI(), request.getRemoteAddr(), ex.getMessage());
        
        ModelAndView mav = new ModelAndView("error/429");
        mav.setStatus(HttpStatus.TOO_MANY_REQUESTS);
        return mav;
    }
    
    /**
     * Handle validation exceptions
     * Spring Boot will automatically serve /error/400.html with i18n support
     */
    @ExceptionHandler({MethodArgumentNotValidException.class, BindException.class, IllegalArgumentException.class})
    public ModelAndView handleValidationException(Exception ex, HttpServletRequest request) {
        logger.warn("Web Validation Exception: {} - IP: {}, Message: {}", 
                   request.getRequestURI(), request.getRemoteAddr(), ex.getMessage());
        
        ModelAndView mav = new ModelAndView("error/400");
        mav.setStatus(HttpStatus.BAD_REQUEST);
        return mav;
    }
    
    /**
     * Handle database exceptions
     * Spring Boot will automatically serve /error/500.html with i18n support
     */
    @ExceptionHandler(DataAccessException.class)
    public ModelAndView handleDataAccessException(DataAccessException ex, HttpServletRequest request) {
        logger.error("Web Database Error: {} - IP: {}, Message: {}", 
                    request.getRequestURI(), request.getRemoteAddr(), ex.getMessage(), ex);
        
        ModelAndView mav = new ModelAndView("error/500");
        mav.setStatus(HttpStatus.INTERNAL_SERVER_ERROR);
        return mav;
    }
    
    /**
     * Handle generic exceptions
     * Spring Boot will automatically serve /error/500.html with i18n support
     */
    @ExceptionHandler(Exception.class)
    public ModelAndView handleGenericException(Exception ex, HttpServletRequest request) {
        logger.error("Web Unhandled Exception: {} - IP: {}, Message: {}", 
                    request.getRequestURI(), request.getRemoteAddr(), ex.getMessage(), ex);
        
        ModelAndView mav = new ModelAndView("error/500");
        mav.setStatus(HttpStatus.INTERNAL_SERVER_ERROR);
        return mav;
    }
    
    /**
     * Resolve locale for authentication error messages
     * Uses simplified locale resolution for session error storage
     */
    private Locale resolveLocale(HttpServletRequest request) {
        try {
            // Use Spring's locale resolver (cookie-based for web)
            Locale resolvedLocale = localeResolver.resolveLocale(request);
            if (resolvedLocale != null && isSupported(resolvedLocale)) {
                return resolvedLocale;
            }
        } catch (Exception e) {
            logger.debug("Failed to resolve locale using LocaleResolver: {}", e.getMessage());
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