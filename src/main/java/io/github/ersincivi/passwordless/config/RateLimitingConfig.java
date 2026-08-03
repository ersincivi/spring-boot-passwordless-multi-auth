package io.github.ersincivi.passwordless.config;

import io.github.ersincivi.passwordless.service.DistributedRateLimitingService;
import io.github.ersincivi.passwordless.exception.RateLimitExceededException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.HandlerInterceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.annotation.*;
import java.util.concurrent.TimeUnit;

/**
 * Rate limiting configuration with interceptor support
 */
@Configuration
public class RateLimitingConfig implements WebMvcConfigurer {
    
    private static final Logger logger = LoggerFactory.getLogger(RateLimitingConfig.class);
    
    @Autowired
    private DistributedRateLimitingService rateLimitingService;
    
    /**
     * Register rate limiting interceptor
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new RateLimitingInterceptor())
                .addPathPatterns("/api/**", "/login", "/verify-otp", "/totp", "/admin")
                .excludePathPatterns("/api/public/**", "/css/**", "/js/**", "/images/**");
    }
    
    /**
     * Rate limiting interceptor for HTTP requests
     */
    public class RateLimitingInterceptor implements HandlerInterceptor {
        
        @Override
        public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
            String path = request.getRequestURI();
            String method = request.getMethod();
            String key = request.getRemoteAddr() + ":" + path + ":" + method;
            
            // Apply different rate limits based on endpoint
            String rateLimitType = getRateLimitType(path);

            logger.info("Rate limiting check. IP: {}, Path: {}, Method: {}, Algorithm: {}", 
                           request.getRemoteAddr(), path, method, rateLimitType);
            
            if (rateLimitType != null) {
                DistributedRateLimitingService.RateLimitResult result = 
                    rateLimitingService.isAllowed(key, rateLimitType);

                    logger.info("Rate limiting result. IP: {}, Path: {}, Algorithm: {}, Remaining: {}, Limit: {}", 
                               request.getRemoteAddr(), path, result.getAlgorithm(), result.getRemaining(), result.getLimit());
                
                if (!result.isAllowed()) {
                    // Rate limit exceeded - throw exception to be handled by appropriate exception handler
                    logger.warn("Rate limit exceeded for IP: {}, Path: {}, Algorithm: {}", 
                               request.getRemoteAddr(), path, result.getAlgorithm());
                    
                    // Add rate limit headers before throwing exception
                    response.setHeader("X-RateLimit-Limit", String.valueOf(result.getLimit()));
                    response.setHeader("X-RateLimit-Remaining", "0");
                    response.setHeader("X-RateLimit-Reset", String.valueOf(System.currentTimeMillis() + 60000)); // 1 minute
                    
                    throw new RateLimitExceededException("Rate limit exceeded: " + result.getMessage());
                } else {
                    // Record successful request
                    rateLimitingService.recordAction(key, rateLimitType);
                    
                    // Add rate limit headers for successful requests
                    response.setHeader("X-RateLimit-Limit", String.valueOf(result.getLimit()));
                    response.setHeader("X-RateLimit-Remaining", String.valueOf(result.getRemaining()));
                }
            }
            
            return true;
        }
        
        private String getRateLimitType(String path) {

            if (path.startsWith("/login") || path.contains("/auth/")) {
                return DistributedRateLimitingService.LOGIN_ATTEMPTS;
            } else if (path.startsWith("/api/")) {
                return DistributedRateLimitingService.API_REQUESTS;
            } else if (path.contains("/verify-otp")) {
                return DistributedRateLimitingService.OTP_VERIFICATION;
            }else if (path.contains("/totp")) {
                return DistributedRateLimitingService.TOTP_VERIFICATION;
            } else if (path.contains("/admin")) {
                return DistributedRateLimitingService.ADMIN_ACTIONS;
            }
            
            // Default rate limiting for other paths
            return DistributedRateLimitingService.API_REQUESTS;
        }
    }
}

/**
 * Annotation for method-level rate limiting
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@interface RateLimit {
    
    /**
     * Rate limit type (uses predefined configurations)
     */
    String value() default "API_REQUESTS";
    
    /**
     * Custom rate limit (requests per time period)
     */
    int limit() default -1;
    
    /**
     * Time period duration
     */
    int duration() default -1;
    
    /**
     * Time unit for the duration
     */
    TimeUnit timeUnit() default TimeUnit.MINUTES;
    
    /**
     * Rate limiting algorithm
     */
    DistributedRateLimitingService.RateLimitAlgorithm algorithm() default DistributedRateLimitingService.RateLimitAlgorithm.FIXED_WINDOW;
    
    /**
     * Key generation strategy
     */
    String keyExpression() default "#{T(java.util.Optional).ofNullable(#request?.getRemoteAddr()).orElse('unknown')}";
    
    /**
     * Error message when rate limit is exceeded
     */
    String message() default "Rate limit exceeded";
}