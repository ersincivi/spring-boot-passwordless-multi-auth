package io.github.ersincivi.passwordless.config;

import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;

import jakarta.servlet.http.HttpServletRequest;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

@Configuration
public class LocaleConfig implements WebMvcConfigurer {

    // Supported languages as per project specification
    private static final List<Locale> SUPPORTED_LOCALES = Arrays.asList(
        Locale.ENGLISH,               // en
        Locale.of("tr", "TR"),
        // new Locale("tr", "TR"),   // tr (Turkish)
        Locale.GERMAN               // de
    );

    @Bean
    public MessageSource messageSource() {
        ReloadableResourceBundleMessageSource source = new ReloadableResourceBundleMessageSource();
        source.setBasename("classpath:messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        source.setDefaultLocale(Locale.ENGLISH);
        source.setCacheSeconds(300); // 5 minutes cache for better performance
        return source;
    }

    /**
     * Primary locale resolver for web requests (cookie-based)
     * Provides persistent language selection for web interface
     * This resolver supports setLocale() for language switching via URL parameters
     * IMPORTANT: Using both explicit name and @Primary to override Spring Boot's default
     */
    @Bean(name = {"localeResolver", "webLocaleResolver"})
    @Primary
    public CookieLocaleResolver webLocaleResolver() {
        CookieLocaleResolver resolver = new CookieLocaleResolver("LOCALE");
        resolver.setDefaultLocale(Locale.ENGLISH);
        // resolver.setCookieName("LOCALE");
        resolver.setCookieMaxAge(Duration.ofDays(30));
        resolver.setCookieSecure(true); // Enhanced security
        resolver.setCookieHttpOnly(true); // Prevent XSS attacks
        resolver.setCookieSameSite("Strict"); // Enhanced CSRF protection
        return resolver;
    }

    /**
     * API-specific locale resolver (Accept-Language header-based)
     * Provides stateless language detection for API requests
     * Note: This is NOT the primary resolver - used only for API context
     */
    @Bean("apiLocaleResolver")
    public AcceptHeaderLocaleResolver apiLocaleResolver() {
        AcceptHeaderLocaleResolver resolver = new AcceptHeaderLocaleResolver() {
            @Override
            public Locale resolveLocale(HttpServletRequest request) {
                // Enhanced locale resolution for API requests
                String requestUri = request.getRequestURI();
                
                // For API requests, prioritize Accept-Language header
                if (requestUri.startsWith("/api/")) {
                    return resolveApiLocale(request);
                }
                
                // For web requests, use default behavior
                return super.resolveLocale(request);
            }
            
            private Locale resolveApiLocale(HttpServletRequest request) {
                // 1. Check for explicit lang parameter (highest priority)
                String langParam = request.getParameter("lang");
                if (langParam != null) {
                    Locale explicitLocale = parseLocale(langParam);
                    if (isSupported(explicitLocale)) {
                        return explicitLocale;
                    }
                }
                
                // 2. Check Accept-Language header
                String acceptLanguage = request.getHeader("Accept-Language");
                if (acceptLanguage != null) {
                    List<Locale> preferredLocales = Locale.LanguageRange.parse(acceptLanguage)
                        .stream()
                        .map(range -> Locale.forLanguageTag(range.getRange()))
                        .toList();
                    
                    for (Locale preferred : preferredLocales) {
                        if (isSupported(preferred)) {
                            return preferred;
                        }
                    }
                }
                
                // 3. Fallback to default
                return Locale.ENGLISH;
            }
        };
        
        resolver.setSupportedLocales(SUPPORTED_LOCALES);
        resolver.setDefaultLocale(Locale.ENGLISH);
        return resolver;
    }

    @Bean
    public LocaleChangeInterceptor localeChangeInterceptor() {
        LocaleChangeInterceptor interceptor = new LocaleChangeInterceptor();
        interceptor.setParamName("lang");
        // Enhanced security: validate locale parameter
        interceptor.setIgnoreInvalidLocale(true);
        return interceptor;
    }

    /**
     * API-specific locale change interceptor
     * Handles locale changes for API endpoints with additional validation
     */
    @Bean
    public LocaleChangeInterceptor apiLocaleChangeInterceptor() {
        LocaleChangeInterceptor interceptor = new LocaleChangeInterceptor() {
            @Override
            public boolean preHandle(HttpServletRequest request, jakarta.servlet.http.HttpServletResponse response, Object handler) {
                String requestUri = request.getRequestURI();
                
                // Only process API requests
                if (requestUri.startsWith("/api/")) {
                    String langParam = request.getParameter("lang");
                    if (langParam != null) {
                        Locale locale = parseLocale(langParam);
                        if (isSupported(locale)) {
                            // Set locale in request attribute for API controllers
                            request.setAttribute("api.locale", locale);
                        } else {
                            // Log security event for invalid locale attempt
                            org.slf4j.LoggerFactory.getLogger("security")
                                .warn("Invalid locale parameter attempted: {} from IP: {}", 
                                     langParam, request.getRemoteAddr());
                        }
                    }
                }
                return true;
            }
        };
        return interceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // Web locale interceptor (all paths)
        registry.addInterceptor(localeChangeInterceptor())
                .addPathPatterns("/**")
                .excludePathPatterns("/api/**");
        
        // API locale interceptor (API paths only)
        registry.addInterceptor(apiLocaleChangeInterceptor())
                .addPathPatterns("/api/**");
    }

    /**
     * Utility methods for locale validation and parsing
     */
    private static Locale parseLocale(String lang) {
        if (lang == null || lang.trim().isEmpty()) {
            return Locale.ENGLISH;
        }
        
        // Security: sanitize input
        String cleanLang = lang.trim().toLowerCase();
        if (cleanLang.matches("^[a-z]{2}(-[A-Z]{2})?$")) {
            return Locale.forLanguageTag(cleanLang);
        }
        
        return Locale.ENGLISH;
    }

    private static boolean isSupported(Locale locale) {
        return SUPPORTED_LOCALES.stream()
                .anyMatch(supported -> supported.getLanguage().equals(locale.getLanguage()));
    }

    /**
     * Get list of supported locales for external use
     */
    public static List<Locale> getSupportedLocales() {
        return SUPPORTED_LOCALES;
    }
}


