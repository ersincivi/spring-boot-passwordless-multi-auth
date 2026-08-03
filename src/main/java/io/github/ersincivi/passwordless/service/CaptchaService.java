package io.github.ersincivi.passwordless.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import jakarta.servlet.http.HttpServletRequest;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Comprehensive CAPTCHA Service for protecting against automated attacks
 * Provides visual CAPTCHA generation, validation, and management
 */
@Service
public class CaptchaService {
    
    private static final Logger logger = LoggerFactory.getLogger(CaptchaService.class);
    
    @Autowired
    private StringRedisTemplate redisTemplate;
    
    @Autowired
    private ObjectMapper objectMapper;
    
    @Autowired
    private SecurityAuditService securityAuditService;
    
    @Autowired
    private WebI18nMessageService webI18nMessageService;
    
    @Value("${app.captcha.enabled:true}")
    private boolean captchaEnabled;
    
    @Value("${app.captcha.length:5}")
    private int captchaLength;
    
    @Value("${app.captcha.width:200}")
    private int captchaWidth;
    
    @Value("${app.captcha.height:80}")
    private int captchaHeight;
    
    @Value("${app.captcha.ttl:300}")
    private int captchaTtlSeconds;
    
    @Value("${app.captcha.threshold:3}")
    private int failureThreshold;
    
    // Redis key prefixes
    private static final String CAPTCHA_PREFIX = "captcha:";
    private static final String CAPTCHA_ATTEMPTS_PREFIX = "captcha_attempts:";
    private static final String CAPTCHA_REQUIRED_PREFIX = "captcha_required:";
    private static final String CAPTCHA_STATS_PREFIX = "captcha_stats:";
    
    // CAPTCHA characters (excluding confusing ones like 0, O, 1, l, I)
    private static final String CAPTCHA_CHARS = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    private static final SecureRandom random = new SecureRandom();
    
    // Colors for CAPTCHA generation
    private static final Color[] BACKGROUND_COLORS = {
        new Color(240, 248, 255), // Alice blue
        new Color(250, 250, 250), // White smoke
        new Color(248, 248, 255), // Ghost white
        new Color(245, 245, 245)  // White smoke
    };
    
    private static final Color[] TEXT_COLORS = {
        new Color(0, 0, 139),     // Dark blue
        new Color(139, 0, 0),     // Dark red
        new Color(0, 100, 0),     // Dark green
        new Color(139, 69, 19),   // Saddle brown
        new Color(72, 61, 139)    // Dark slate blue
    };
    
    /**
     * Check if CAPTCHA is required for the given IP/username
     */
    public boolean isCaptchaRequired(String identifier) {
        if (!captchaEnabled) {
            return false;
        }
        
        try {
            String requiredKey = CAPTCHA_REQUIRED_PREFIX + identifier;
            return Boolean.TRUE.equals(redisTemplate.hasKey(requiredKey));
        } catch (Exception e) {
            logger.error("Error checking if CAPTCHA is required for: {}", identifier, e);
            return true; // Fail safe - require CAPTCHA on error
        }
    }
    
    /**
     * Record a failed authentication attempt and determine if CAPTCHA should be required
     */
    public boolean recordFailedAttempt(String identifier, String ipAddress, String userAgent) {
        try {
            String attemptsKey = CAPTCHA_ATTEMPTS_PREFIX + identifier;
            String requiredKey = CAPTCHA_REQUIRED_PREFIX + identifier;
            
            // Increment failure count
            Long failureCount = redisTemplate.opsForValue().increment(attemptsKey);
            redisTemplate.expire(attemptsKey, 1, TimeUnit.HOURS);
            
            // Check if threshold is reached
            if (failureCount >= failureThreshold) {
                // Mark CAPTCHA as required
                CaptchaRequirement requirement = new CaptchaRequirement(
                    identifier, ipAddress, userAgent, 
                    LocalDateTime.now(), failureCount.intValue());
                
                String requirementJson = objectMapper.writeValueAsString(requirement);
                redisTemplate.opsForValue().set(requiredKey, requirementJson, 24, TimeUnit.HOURS);
                
                // Log security event
                Map<String, Object> details = new HashMap<>();
                details.put("identifier", identifier);
                details.put("failureCount", failureCount);
                details.put("threshold", failureThreshold);
                
                securityAuditService.logSecurityViolation(
                    identifier, "CAPTCHA_REQUIRED", "Multiple failed attempts detected", 
                    ipAddress, userAgent, details);
                
                logger.warn("CAPTCHA now required for identifier: {}, failures: {}", identifier, failureCount);
                return true;
            }
            
            return false;
            
        } catch (Exception e) {
            logger.error("Error recording failed attempt for: {}", identifier, e);
            return true; // Fail safe - require CAPTCHA on error
        }
    }
    
    /**
     * Generate a new CAPTCHA challenge
     */
    public CaptchaChallenge generateCaptcha(String sessionId, String ipAddress) {
        try {
            // Generate random text
            String captchaText = generateCaptchaText();
            
            // Create CAPTCHA image
            byte[] imageBytes = createCaptchaImage(captchaText);
            String imageBase64 = Base64.getEncoder().encodeToString(imageBytes);
            
            // Store CAPTCHA data in Redis
            CaptchaData captchaData = new CaptchaData(
                captchaText, sessionId, ipAddress, 
                LocalDateTime.now(), false);
            
            String captchaKey = CAPTCHA_PREFIX + sessionId;
            String captchaJson = objectMapper.writeValueAsString(captchaData);
            redisTemplate.opsForValue().set(captchaKey, captchaJson, captchaTtlSeconds, TimeUnit.SECONDS);
            
            // Update statistics
            updateCaptchaStatistics("generated");
            
            logger.debug("CAPTCHA generated for session: {}, IP: {}", sessionId, ipAddress);
            
            return new CaptchaChallenge(sessionId, imageBase64, captchaTtlSeconds);
            
        } catch (Exception e) {
            logger.error("Error generating CAPTCHA for session: {}", sessionId, e);
            throw new RuntimeException("Failed to generate CAPTCHA", e);
        }
    }
    
    /**
     * Validate CAPTCHA response with internationalized messages
     */
    public CaptchaValidationResult validateCaptcha(String sessionId, String userInput, String ipAddress, String userAgent) {
        return validateCaptcha(sessionId, userInput, ipAddress, userAgent, null);
    }
    
    /**
     * Validate CAPTCHA response with internationalized messages
     */
    public CaptchaValidationResult validateCaptcha(String sessionId, String userInput, String ipAddress, String userAgent, HttpServletRequest request) {
        if (!captchaEnabled) {
            String disabledMessage = getLocalizedMessage("captcha.disabled", "CAPTCHA disabled", request);
            return new CaptchaValidationResult(true, disabledMessage, false);
        }
        
        try {
            String captchaKey = CAPTCHA_PREFIX + sessionId;
            String captchaJson = redisTemplate.opsForValue().get(captchaKey);
            
            if (captchaJson == null) {
                updateCaptchaStatistics("expired");
                String expiredMessage = getLocalizedMessage("captcha.expired", "CAPTCHA expired or not found", request);
                return new CaptchaValidationResult(false, expiredMessage, true);
            }
            
            CaptchaData captchaData = objectMapper.readValue(captchaJson, CaptchaData.class);
            
            // Check if already used
            if (captchaData.isUsed()) {
                updateCaptchaStatistics("already_used");
                String usedMessage = getLocalizedMessage("captcha.already.used", "CAPTCHA already used", request);
                return new CaptchaValidationResult(false, usedMessage, true);
            }

            // Validate input
            boolean isValid = captchaData.getText().equalsIgnoreCase(userInput != null ? userInput.trim() : "");
            
            if (isValid) {
                // Mark as used and remove from Redis
                redisTemplate.delete(captchaKey);
                updateCaptchaStatistics("validated_success");
                
                // Log successful validation
                Map<String, Object> details = new HashMap<>();
                details.put("sessionId", sessionId);
                details.put("ipAddress", ipAddress);
                
                securityAuditService.logAuthenticationEvent(
                    "SYSTEM", "CAPTCHA_VALIDATED", "SUCCESS", ipAddress, userAgent, details);
                
                logger.debug("CAPTCHA validation successful for session: {}", sessionId);
                String successMessage = getLocalizedMessage("captcha.validation.successful", "CAPTCHA validation successful", request);
                return new CaptchaValidationResult(true, successMessage, false);
                
            } else {
                // Mark as used to prevent brute force
                captchaData.setUsed(true);
                String updatedJson = objectMapper.writeValueAsString(captchaData);
                redisTemplate.opsForValue().set(captchaKey, updatedJson, 60, TimeUnit.SECONDS);
                
                updateCaptchaStatistics("validation_failed");
                
                // Log failed validation
                Map<String, Object> details = new HashMap<>();
                details.put("sessionId", sessionId);
                details.put("ipAddress", ipAddress);
                details.put("expectedLength", captchaData.getText().length());
                details.put("providedLength", userInput != null ? userInput.length() : 0);
                
                securityAuditService.logSecurityViolation(
                    "SYSTEM", "CAPTCHA_VALIDATION_FAILED", "Invalid CAPTCHA response", 
                    ipAddress, userAgent, details);
                
                logger.warn("CAPTCHA validation failed for session: {}, IP: {}", sessionId, ipAddress);
                String invalidMessage = getLocalizedMessage("captcha.invalid", "Invalid CAPTCHA", request);
                return new CaptchaValidationResult(false, invalidMessage, true);
            }
            
        } catch (Exception e) {
            logger.error("Error validating CAPTCHA for session: {}", sessionId, e);
            updateCaptchaStatistics("validation_error");
            String errorMessage = getLocalizedMessage("captcha.validation.error", "CAPTCHA validation error", request);
            return new CaptchaValidationResult(false, errorMessage, true);
        }
    }
    
    /**
     * Clear CAPTCHA requirement after successful authentication
     */
    public void clearCaptchaRequirement(String identifier) {
        try {
            String attemptsKey = CAPTCHA_ATTEMPTS_PREFIX + identifier;
            String requiredKey = CAPTCHA_REQUIRED_PREFIX + identifier;
            
            redisTemplate.delete(attemptsKey);
            redisTemplate.delete(requiredKey);
            
            logger.debug("CAPTCHA requirement cleared for identifier: {}", identifier);
            
        } catch (Exception e) {
            logger.error("Error clearing CAPTCHA requirement for: {}", identifier, e);
        }
    }
    
    /**
     * Get CAPTCHA statistics
     */
    public Map<String, Object> getCaptchaStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        try {
            // Get all statistics keys
            Set<String> statsKeys = redisTemplate.keys(CAPTCHA_STATS_PREFIX + "*");
            
            Map<String, Integer> statistics = new HashMap<>();
            if (statsKeys != null) {
                for (String key : statsKeys) {
                    String statType = key.substring(CAPTCHA_STATS_PREFIX.length());
                    String value = redisTemplate.opsForValue().get(key);
                    statistics.put(statType, value != null ? Integer.parseInt(value) : 0);
                }
            }
            
            // Get active CAPTCHA count
            Set<String> captchaKeys = redisTemplate.keys(CAPTCHA_PREFIX + "*");
            int activeCaptchas = captchaKeys != null ? captchaKeys.size() : 0;
            
            // Get CAPTCHA requirements count
            Set<String> requiredKeys = redisTemplate.keys(CAPTCHA_REQUIRED_PREFIX + "*");
            int captchaRequiredCount = requiredKeys != null ? requiredKeys.size() : 0;
            
            stats.put("captchaEnabled", captchaEnabled);
            stats.put("captchaLength", captchaLength);
            stats.put("captchaTtlSeconds", captchaTtlSeconds);
            stats.put("failureThreshold", failureThreshold);
            stats.put("activeCaptchas", activeCaptchas);
            stats.put("captchaRequiredCount", captchaRequiredCount);
            stats.put("statistics", statistics);
            stats.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            
        } catch (Exception e) {
            logger.error("Error getting CAPTCHA statistics", e);
            stats.put("error", "Failed to retrieve statistics");
        }
        
        return stats;
    }
    
    /**
     * Admin function to force CAPTCHA requirement for an identifier
     */
    public boolean forceCaptchaRequirement(String identifier, String adminUser, String reason) {
        try {
            String requiredKey = CAPTCHA_REQUIRED_PREFIX + identifier;
            
            CaptchaRequirement requirement = new CaptchaRequirement(
                identifier, "ADMIN_FORCED", adminUser, 
                LocalDateTime.now(), 999);
            
            String requirementJson = objectMapper.writeValueAsString(requirement);
            redisTemplate.opsForValue().set(requiredKey, requirementJson, 24, TimeUnit.HOURS);
            
            // Log admin action
            Map<String, Object> details = new HashMap<>();
            details.put("identifier", identifier);
            details.put("reason", reason);
            details.put("adminUser", adminUser);
            
            securityAuditService.logAdminAction(
                adminUser, "CAPTCHA_FORCED", identifier, "SUCCESS", "ADMIN", details);
            
            logger.info("CAPTCHA requirement forced for identifier: {} by admin: {}, reason: {}", 
                       identifier, adminUser, reason);
            
            return true;
            
        } catch (Exception e) {
            logger.error("Error forcing CAPTCHA requirement for: {}", identifier, e);
            return false;
        }
    }
    
    // Private helper methods
    
    /**
     * Get localized message with fallback to default
     */
    private String getLocalizedMessage(String key, String defaultMessage, HttpServletRequest request) {
        if (request != null) {
            return webI18nMessageService.getMessage(key, null, defaultMessage, request);
        }
        return defaultMessage;
    }
    
    private String generateCaptchaText() {
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < captchaLength; i++) {
            text.append(CAPTCHA_CHARS.charAt(random.nextInt(CAPTCHA_CHARS.length())));
        }
        return text.toString();
    }
    
    private byte[] createCaptchaImage(String text) throws IOException {
        BufferedImage image = new BufferedImage(captchaWidth, captchaHeight, BufferedImage.TYPE_INT_RGB);
        Graphics2D g2d = image.createGraphics();
        
        // Enable antialiasing
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2d.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        
        // Set background
        Color backgroundColor = BACKGROUND_COLORS[random.nextInt(BACKGROUND_COLORS.length)];
        g2d.setColor(backgroundColor);
        g2d.fillRect(0, 0, captchaWidth, captchaHeight);
        
        // Add noise lines
        addNoiseLines(g2d);
        
        // Draw text
        drawCaptchaText(g2d, text);
        
        // Add noise dots
        addNoiseDots(g2d);
        
        g2d.dispose();
        
        // Convert to byte array
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, "PNG", baos);
        return baos.toByteArray();
    }
    
    private void addNoiseLines(Graphics2D g2d) {
        g2d.setStroke(new BasicStroke(2));
        for (int i = 0; i < 5; i++) {
            Color lineColor = TEXT_COLORS[random.nextInt(TEXT_COLORS.length)];
            g2d.setColor(new Color(lineColor.getRed(), lineColor.getGreen(), lineColor.getBlue(), 60));
            
            int x1 = random.nextInt(captchaWidth);
            int y1 = random.nextInt(captchaHeight);
            int x2 = random.nextInt(captchaWidth);
            int y2 = random.nextInt(captchaHeight);
            
            g2d.drawLine(x1, y1, x2, y2);
        }
    }
    
    private void drawCaptchaText(Graphics2D g2d, String text) {
        // Font baseFont = new Font("Arial", Font.BOLD, 32);
        int charWidth = captchaWidth / text.length();
        
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            
            // Random font size and style
            int fontSize = 28 + random.nextInt(8);
            int fontStyle = random.nextBoolean() ? Font.BOLD : Font.PLAIN;
            Font charFont = new Font("Arial", fontStyle, fontSize);
            g2d.setFont(charFont);
            
            // Random color
            Color textColor = TEXT_COLORS[random.nextInt(TEXT_COLORS.length)];
            g2d.setColor(textColor);
            
            // Random position with slight rotation
            int x = charWidth * i + random.nextInt(10) + 10;
            int y = captchaHeight / 2 + random.nextInt(10) + 5;
            
            // Slight rotation
            double angle = (random.nextDouble() - 0.5) * 0.5; // -0.25 to 0.25 radians
            g2d.rotate(angle, x, y);
            
            g2d.drawString(String.valueOf(ch), x, y);
            
            // Reset rotation
            g2d.rotate(-angle, x, y);
        }
    }
    
    private void addNoiseDots(Graphics2D g2d) {
        for (int i = 0; i < 50; i++) {
            Color dotColor = TEXT_COLORS[random.nextInt(TEXT_COLORS.length)];
            g2d.setColor(new Color(dotColor.getRed(), dotColor.getGreen(), dotColor.getBlue(), 100));
            
            int x = random.nextInt(captchaWidth);
            int y = random.nextInt(captchaHeight);
            int size = 1 + random.nextInt(3);
            
            g2d.fillOval(x, y, size, size);
        }
    }
    
    private void updateCaptchaStatistics(String statType) {
        try {
            String statsKey = CAPTCHA_STATS_PREFIX + statType;
            redisTemplate.opsForValue().increment(statsKey);
            redisTemplate.expire(statsKey, 30, TimeUnit.DAYS);
        } catch (Exception e) {
            logger.warn("Failed to update CAPTCHA statistics for: {}", statType, e);
        }
    }
    
    // Data classes
    
    public static class CaptchaChallenge {
        private final String sessionId;
        private final String imageBase64;
        private final int ttlSeconds;
        
        public CaptchaChallenge(String sessionId, String imageBase64, int ttlSeconds) {
            this.sessionId = sessionId;
            this.imageBase64 = imageBase64;
            this.ttlSeconds = ttlSeconds;
        }
        
        public String getSessionId() { return sessionId; }
        public String getImageBase64() { return imageBase64; }
        public int getTtlSeconds() { return ttlSeconds; }
    }
    
    public static class CaptchaValidationResult {
        private final boolean valid;
        private final String message;
        private final boolean regenerateRequired;
        
        public CaptchaValidationResult(boolean valid, String message, boolean regenerateRequired) {
            this.valid = valid;
            this.message = message;
            this.regenerateRequired = regenerateRequired;
        }
        
        public boolean isValid() { return valid; }
        public String getMessage() { return message; }
        public boolean isRegenerateRequired() { return regenerateRequired; }
    }
    
    public static class CaptchaData {
        private String text;
        private String sessionId;
        private String ipAddress;
        private LocalDateTime createdAt;
        private boolean used;
        
        public CaptchaData() {}
        
        public CaptchaData(String text, String sessionId, String ipAddress, 
                          LocalDateTime createdAt, boolean used) {
            this.text = text;
            this.sessionId = sessionId;
            this.ipAddress = ipAddress;
            this.createdAt = createdAt;
            this.used = used;
        }
        
        // Getters and setters
        public String getText() { return text; }
        public void setText(String text) { this.text = text; }
        
        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }
        
        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
        
        public LocalDateTime getCreatedAt() { return createdAt; }
        public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
        
        public boolean isUsed() { return used; }
        public void setUsed(boolean used) { this.used = used; }
    }
    
    public static class CaptchaRequirement {
        private String identifier;
        private String ipAddress;
        private String userAgent;
        private LocalDateTime requiredAt;
        private int failureCount;
        
        public CaptchaRequirement() {}
        
        public CaptchaRequirement(String identifier, String ipAddress, String userAgent, 
                                 LocalDateTime requiredAt, int failureCount) {
            this.identifier = identifier;
            this.ipAddress = ipAddress;
            this.userAgent = userAgent;
            this.requiredAt = requiredAt;
            this.failureCount = failureCount;
        }
        
        // Getters and setters
        public String getIdentifier() { return identifier; }
        public void setIdentifier(String identifier) { this.identifier = identifier; }
        
        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
        
        public String getUserAgent() { return userAgent; }
        public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
        
        public LocalDateTime getRequiredAt() { return requiredAt; }
        public void setRequiredAt(LocalDateTime requiredAt) { this.requiredAt = requiredAt; }
        
        public int getFailureCount() { return failureCount; }
        public void setFailureCount(int failureCount) { this.failureCount = failureCount; }
    }
}