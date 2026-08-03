package io.github.ersincivi.passwordless.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;

import java.io.IOException;
import java.util.Arrays;
import java.util.Set;
import java.util.HashSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.stream.Collectors;

/**
 * Enhanced CSRF Filter implementing Double Submit Cookie Pattern and Origin
 * Validation
 */
@Component
public class EnhancedCsrfFilter extends StaticResourceIgnoringFilter {

    private static final Logger logger = LoggerFactory.getLogger(EnhancedCsrfFilter.class);

    // Allowed origins for CSRF requests (configure based on your environment)
    // Updated to match CORS configuration from application.yml
    private Set<String> allowedOrigins;

    public EnhancedCsrfFilter(@Value("${app.cors.allowed-origins}") String allowedOriginsCsv) {

        try {
            // Remove quotes if present and trim whitespace
            String cleanedOrigins = allowedOriginsCsv != null ? allowedOriginsCsv.replace("\"", "").trim() : "";
            if (cleanedOrigins.isEmpty()) {
                this.allowedOrigins = new HashSet<>();
                logger.warn("No allowed origins configured for CSRF filter");
                return;
            }

            String[] originsArray = cleanedOrigins.split(",");
            this.allowedOrigins = new HashSet<>(Arrays.asList(originsArray));
            // Trim whitespace from each origin
            this.allowedOrigins = this.allowedOrigins.stream().map(String::trim).collect(Collectors.toSet());

            logger.info("Allowed origins: {}", this.allowedOrigins);
        } catch (Exception e) {
            logger.error("Error parsing allowed origins: {}", e.getMessage(), e);
            this.allowedOrigins = new HashSet<>();
        }
    }

    // CSRF attack monitoring
    private final ConcurrentHashMap<String, CsrfAttackInfo> attackMonitoring = new ConcurrentHashMap<>();
    private final AtomicLong csrfAttackCounter = new AtomicLong(0);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        // Only validate CSRF for state-changing operations
        if ("POST".equals(request.getMethod()) ||
                "PUT".equals(request.getMethod()) ||
                "DELETE".equals(request.getMethod()) ||
                "PATCH".equals(request.getMethod())) {

            // Skip validation for excluded paths
            String requestPath = request.getRequestURI();
            if (shouldSkipCsrfValidation(requestPath)) {
                filterChain.doFilter(request, response);
                return;
            }

            // Perform enhanced CSRF validation
            CsrfValidationResult validationResult = performEnhancedCsrfValidation(request);

            if (!validationResult.isValid()) {
                handleCsrfViolation(request, response, validationResult);
                return;
            }

            // Log successful validation
            logger.info("Enhanced CSRF validation passed - IP: {}, Path: {}, Method: {}",
                    request.getRemoteAddr(), requestPath, request.getMethod());
        }

        filterChain.doFilter(request, response);
    }

    private CsrfValidationResult performEnhancedCsrfValidation(HttpServletRequest request) {
        // 1. Origin Header Validation
        CsrfValidationResult originValidation = validateOriginHeader(request);
        if (!originValidation.isValid()) {
            return originValidation;
        }

        // 2. Double Submit Cookie Pattern Validation
        CsrfValidationResult doubleSubmitValidation = validateDoubleSubmitPattern(request);
        if (!doubleSubmitValidation.isValid()) {
            return doubleSubmitValidation;
        }

        // 3. Token Age and Format Validation
        CsrfValidationResult tokenValidation = validateTokenSecurity(request);
        if (!tokenValidation.isValid()) {
            return tokenValidation;
        }

        return CsrfValidationResult.valid();
    }

    private CsrfValidationResult validateOriginHeader(HttpServletRequest request) {
        String origin = request.getHeader("Origin");
        String referer = request.getHeader("Referer");
        String host = request.getHeader("Host");
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();

        // For same-origin requests, Origin header may be null
        // In such cases, we should allow the request if it's from the same server

        logger.debug("Validating Origin header. Origin value: '{}', Origin class: {}",
                origin, origin != null ? origin.getClass().getName() : "null");

        // Handle case where Origin header is the literal string "null" (common in some
        // browsers)
        if (origin == null || (origin != null
                && (origin.trim().isEmpty() || origin.trim().equals("null") || "null".equals(origin)))) {
            logger.debug("Origin is null, checking for localhost request");
            // If Origin is null, this is likely a same-origin request
            // Check if this is a same-origin request by comparing with server details

            logger.debug("EnhancedCsrfFilter, Check Client IP: {}", request.getRemoteAddr());

            // For localhost requests, we should allow them as they are same-origin
            if (isLocalhostRequest(request.getRemoteAddr(), host, serverName, serverPort)) {
                logger.debug("Localhost request detected. Login allowed.");
                return CsrfValidationResult.valid();
            }

            logger.debug("Not a localhost request, checking Referer header");

            // If Origin is null but not a localhost request, check Referer header
            if (referer != null) {
                logger.debug("Referer header present: {}", referer);
                // Extract the origin from the Referer header
                try {
                    String refererOrigin = getOriginFromUrl(referer);
                    logger.debug("Referer origin: {}", refererOrigin);
                    if (allowedOrigins.contains(refererOrigin)) {
                        // Referer is from an allowed origin, allow the request
                        logger.debug("Referer origin is allowed, allowing request");
                        return CsrfValidationResult.valid();
                    } else {
                        logger.warn("CSRF: Invalid Referer header - IP: {}, Referer: {}",
                                request.getRemoteAddr(), referer);
                        return CsrfValidationResult.invalid("Invalid referer header", "REFERER_VALIDATION_FAILED");
                    }
                } catch (Exception e) {
                    logger.warn("CSRF: Malformed Referer header - IP: {}, Referer: {}",
                            request.getRemoteAddr(), referer);
                    return CsrfValidationResult.invalid("Malformed referer header", "MALFORMED_REFERER");
                }
            } else {
                // Neither Origin nor Referer present
                // This is acceptable for same-origin requests
                logger.debug("CSRF: Missing Origin and Referer headers for same-origin request - IP: {}, Host: {}",
                        request.getRemoteAddr(), host);
                return CsrfValidationResult.valid();
            }
        } else {
            logger.debug("Origin header is present: {}", origin);
            // Origin header is present
            if (!allowedOrigins.contains(origin)) {
                logger.warn("CSRF: Invalid Origin header - IP: {}, Origin: {}",
                        request.getRemoteAddr(), origin);
                return CsrfValidationResult.invalid("Invalid origin header", "ORIGIN_VALIDATION_FAILED");
            } else {
                logger.debug("Origin header is valid: {}", origin);
            }
        }

        return CsrfValidationResult.valid();
    }

    private boolean isLocalhostRequest(String clientIP, String host, String serverName, int serverPort) {
        // Check for common localhost patterns
        if ("127.0.0.1".equals(clientIP) || "0:0:0:0:0:0:0:1".equals(clientIP) || "::1".equals(clientIP)) {
            return true;
        }

        // Check if the Host header matches common localhost patterns
        if (host != null && (host.equals("localhost") || host.equals("127.0.0.1") ||
                host.equals("[::1]") || host.equals("localhost:" + serverPort) ||
                host.equals("127.0.0.1:" + serverPort) || host.equals("[::1]:" + serverPort))) {
            return true;
        }

        // Check if the server name is localhost
        if ("localhost".equals(serverName) || "127.0.0.1".equals(serverName)) {
            return true;
        }

        return false;
    }

    private boolean isSameOriginRequest(HttpServletRequest request) {
        // More sophisticated same-origin detection
        String host = request.getHeader("Host");
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();

        // Check for localhost patterns first
        if (isLocalhostRequest(request.getRemoteAddr(), host, serverName, serverPort)) {
            return true;
        }

        // Check if the Host header matches our server
        if (host != null && (host.equals(serverName + ":" + serverPort) ||
                (serverPort == 80 && host.equals(serverName)) ||
                (serverPort == 443 && host.equals(serverName)))) {
            return true;
        }

        return false;
    }

    private String getOriginFromUrl(String url) {
        try {
            java.net.URL uri = new java.net.URL(url);
            String origin = uri.getProtocol() + "://" + uri.getHost();
            if (uri.getPort() != -1 &&
                    ((uri.getProtocol().equals("http") && uri.getPort() != 80) ||
                            (uri.getProtocol().equals("https") && uri.getPort() != 443))) {
                origin += ":" + uri.getPort();
            }
            return origin;
        } catch (Exception e) {
            throw new RuntimeException("Invalid URL: " + url, e);
        }
    }

    private CsrfValidationResult validateDoubleSubmitPattern(HttpServletRequest request) {
        // Get CSRF token from cookie
        String cookieToken = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            cookieToken = Arrays.stream(cookies)
                    .filter(cookie -> "XSRF-TOKEN".equals(cookie.getName()))
                    .map(Cookie::getValue)
                    .findFirst()
                    .orElse(null);
        }

        if (cookieToken == null) {
            logger.warn("CSRF: Missing CSRF cookie - IP: {}", request.getRemoteAddr());
            return CsrfValidationResult.invalid("Missing CSRF cookie", "MISSING_CSRF_COOKIE");
        }

        // Get CSRF token from header or parameter
        String headerToken = request.getHeader("X-XSRF-TOKEN");
        String parameterToken = request.getParameter("_csrf");

        String submittedToken = headerToken != null ? headerToken : parameterToken;

        if (submittedToken == null) {
            logger.warn("CSRF: Missing CSRF token in request - IP: {}", request.getRemoteAddr());
            return CsrfValidationResult.invalid("Missing CSRF token", "MISSING_CSRF_TOKEN");
        }

        // Validate Double Submit Pattern - cookie and submitted token must match
        if (!cookieToken.equals(submittedToken)) {
            logger.warn("CSRF: Double submit pattern validation failed - IP: {}, Cookie: {}..., Submitted: {}...",
                    request.getRemoteAddr(),
                    cookieToken.substring(0, Math.min(8, cookieToken.length())),
                    submittedToken.substring(0, Math.min(8, submittedToken.length())));
            return CsrfValidationResult.invalid("CSRF token mismatch", "DOUBLE_SUBMIT_PATTERN_FAILED");
        }

        return CsrfValidationResult.valid();
    }

    private CsrfValidationResult validateTokenSecurity(HttpServletRequest request) {
        String token = request.getHeader("X-XSRF-TOKEN");
        if (token == null) {
            token = request.getParameter("_csrf");
        }

        if (token == null) {
            return CsrfValidationResult.invalid("No token present for security validation", "NO_TOKEN_FOR_VALIDATION");
        }

        // Enhanced token format validation (UUID-like pattern)
        if (token.length() < 20 || !token.matches("^[a-fA-F0-9-]+$")) {
            logger.warn("CSRF: Invalid token format - IP: {}, Token: {}...",
                    request.getRemoteAddr(), token.substring(0, Math.min(8, token.length())));
            return CsrfValidationResult.invalid("Invalid token format", "INVALID_TOKEN_FORMAT");
        }

        // Additional entropy check - ensure token has sufficient randomness
        if (!hasValidEntropy(token)) {
            logger.warn("CSRF: Insufficient token entropy - IP: {}", request.getRemoteAddr());
            return CsrfValidationResult.invalid("Insufficient token entropy", "LOW_ENTROPY_TOKEN");
        }

        return CsrfValidationResult.valid();
    }

    private boolean hasValidEntropy(String token) {
        // Simple entropy check - ensure token contains sufficient variety of characters
        Set<Character> uniqueChars = new HashSet<>();
        for (char c : token.toCharArray()) {
            uniqueChars.add(c);
        }

        // Token should have at least 8 unique characters for reasonable entropy
        return uniqueChars.size() >= 8;
    }

    private void handleCsrfViolation(HttpServletRequest request, HttpServletResponse response,
            CsrfValidationResult validationResult) throws IOException {
        String userAgent = request.getHeader("User-Agent");
        String path = request.getRequestURI();

        // Log security violation
        logger.error("Enhanced CSRF validation failed - IP: {}, Path: {}, Reason: {}, Type: {}, UserAgent: {}",
                request.getRemoteAddr(), path, validationResult.getReason(),
                validationResult.getViolationType(), userAgent);

        // Record attack for monitoring
        recordCsrfAttack(request.getRemoteAddr(), validationResult.getViolationType(), path);

        // Respond with 403 Forbidden
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");
        response.getWriter().write(String.format(
                "{\"error\":\"CSRF validation failed\",\"message\":\"%s\",\"timestamp\":\"%s\"}",
                validationResult.getReason(),
                LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)));
    }

    private void recordCsrfAttack(String clientIP, String violationType, String path) {
        String key = clientIP + "_" + violationType;
        CsrfAttackInfo attackInfo = attackMonitoring.computeIfAbsent(key,
                k -> new CsrfAttackInfo(clientIP, violationType));

        attackInfo.incrementCount();
        attackInfo.addPath(path);

        long totalAttacks = csrfAttackCounter.incrementAndGet();

        // Log attack statistics
        logger.warn("CSRF attack recorded - IP: {}, Type: {}, Count: {}, Total CSRF attacks: {}",
                clientIP, violationType, attackInfo.getCount(), totalAttacks);

        // Consider implementing rate limiting or IP blocking for repeated violations
        if (attackInfo.getCount() > 5) {
            logger.error("Multiple CSRF attacks detected from IP: {} - Consider blocking", clientIP);
        }
    }

    private boolean shouldSkipCsrfValidation(String requestPath) {
        return requestPath.startsWith("/actuator/") ||
                requestPath.startsWith("/oauth2/") ||
                requestPath.startsWith("/login/oauth2/") ||
                requestPath.startsWith("/api/") ||
                requestPath.equals("/error") ||
                requestPath.equals("/favicon.ico");
        // Note: We're not skipping /register endpoint as we want to apply our enhanced
        // CSRF protection
    }

    // Helper classes
    private static class CsrfValidationResult {
        private final boolean valid;
        private final String reason;
        private final String violationType;

        private CsrfValidationResult(boolean valid, String reason, String violationType) {
            this.valid = valid;
            this.reason = reason;
            this.violationType = violationType;
        }

        public static CsrfValidationResult valid() {
            return new CsrfValidationResult(true, null, null);
        }

        public static CsrfValidationResult invalid(String reason, String violationType) {
            return new CsrfValidationResult(false, reason, violationType);
        }

        public boolean isValid() {
            return valid;
        }

        public String getReason() {
            return reason;
        }

        public String getViolationType() {
            return violationType;
        }
    }

    private static class CsrfAttackInfo {
        private final String clientIP;
        private final String violationType;
        private final LocalDateTime firstSeen;
        private final Set<String> paths;
        private int count;
        private LocalDateTime lastSeen;

        public CsrfAttackInfo(String clientIP, String violationType) {
            this.clientIP = clientIP;
            this.violationType = violationType;
            this.firstSeen = LocalDateTime.now();
            this.lastSeen = LocalDateTime.now();
            this.paths = new HashSet<>();
            this.count = 0;
        }

        public void incrementCount() {
            this.count++;
            this.lastSeen = LocalDateTime.now();
        }

        public void addPath(String path) {
            this.paths.add(path);
        }

        public int getCount() {
            return count;
        }

        public LocalDateTime getFirstSeen() {
            return firstSeen;
        }

        public LocalDateTime getLastSeen() {
            return lastSeen;
        }

        public Set<String> getPaths() {
            return paths;
        }
    }
}