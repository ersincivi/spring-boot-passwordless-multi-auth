package io.github.ersincivi.passwordless.service;

import io.github.ersincivi.passwordless.config.RateLimitProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Comprehensive Redis-based distributed rate limiting service
 * Supports multiple algorithms: Fixed Window, Sliding Window, Token Bucket, and Leaky Bucket
 */
@Service
public class DistributedRateLimitingService {
    
    private static final Logger logger = LoggerFactory.getLogger(DistributedRateLimitingService.class);
    
    @Autowired
    private StringRedisTemplate redisTemplate;
    
    @Autowired
    private ObjectMapper objectMapper;
    
    @Autowired
    private RateLimitProperties rateLimitProperties;
    
    @Autowired
    private SecurityAuditService securityAuditService;
    
    // Redis key prefixes
    private static final String RATE_LIMIT_PREFIX = "rate_limit:";
    private static final String TOKEN_BUCKET_PREFIX = "token_bucket:";
    private static final String SLIDING_WINDOW_PREFIX = "sliding_window:";
    private static final String LEAKY_BUCKET_PREFIX = "leaky_bucket:";
    
    // Rate limiting algorithms
    public enum RateLimitAlgorithm {
        FIXED_WINDOW,
        SLIDING_WINDOW, 
        TOKEN_BUCKET,
        LEAKY_BUCKET
    }
    
    // Rate limit types as constants
    public static final String LOGIN_ATTEMPTS = "LOGIN_ATTEMPTS";
    public static final String API_REQUESTS = "API_REQUESTS";
    public static final String OTP_VERIFICATION = "OTP_VERIFICATION";
    public static final String TOTP_VERIFICATION = "TOTP_VERIFICATION";
    public static final String ADMIN_ACTIONS = "ADMIN_ACTIONS";
    
    /**
     * Check if an action is allowed under rate limiting
     */
    public RateLimitResult isAllowed(String key, String rateLimitType) {
        RateLimitConfig config = getRateLimitConfig(rateLimitType);
        return isAllowed(key, config.getLimit(), config.getDuration(), 
                        config.getTimeUnit(), config.getAlgorithm());
    }
    
    /**
     * Check if an action is allowed with custom parameters
     */
    public RateLimitResult isAllowed(String key, int limit, int duration, TimeUnit timeUnit, RateLimitAlgorithm algorithm) {
        try {
            switch (algorithm) {
                case FIXED_WINDOW:
                    return checkFixedWindow(key, limit, duration, timeUnit);
                case SLIDING_WINDOW:
                    return checkSlidingWindow(key, limit, duration, timeUnit);
                case TOKEN_BUCKET:
                    return checkTokenBucket(key, limit, duration, timeUnit);
                case LEAKY_BUCKET:
                    return checkLeakyBucket(key, limit, duration, timeUnit);
                default:
                    return new RateLimitResult(false, 0, 0, "Unknown algorithm", algorithm);
            }
        } catch (Exception e) {
            logger.error("Error checking rate limit for key: {}, algorithm: {}", key, algorithm, e);
            // In case of Redis failure, allow the request but log the error
            return new RateLimitResult(true, limit, limit, "Rate limiting service unavailable", algorithm);
        }
    }
    
    /**
     * Record a successful action (consumes rate limit quota)
     */
    public void recordAction(String key, String rateLimitType) {
        RateLimitConfig config = getRateLimitConfig(rateLimitType);
        recordAction(key, config.getLimit(), config.getDuration(), 
                    config.getTimeUnit(), config.getAlgorithm());
    }
    
    /**
     * Record a successful action with custom parameters
     */
    public void recordAction(String key, int limit, int duration, TimeUnit timeUnit, RateLimitAlgorithm algorithm) {
        try {
            switch (algorithm) {
                case FIXED_WINDOW:
                    recordFixedWindow(key, duration, timeUnit);
                    break;
                case SLIDING_WINDOW:
                    recordSlidingWindow(key, duration, timeUnit);
                    break;
                case TOKEN_BUCKET:
                    recordTokenBucket(key, limit, duration, timeUnit);
                    break;
                case LEAKY_BUCKET:
                    recordLeakyBucket(key, limit, duration, timeUnit);
                    break;
            }
            
            // Log rate limit action
            Map<String, Object> details = new HashMap<>();
            details.put("key", key);
            details.put("algorithm", algorithm.name());
            details.put("limit", limit);
            details.put("duration", duration);
            details.put("timeUnit", timeUnit.name());
            
            securityAuditService.logAdminAction("SYSTEM", "RATE_LIMIT_RECORDED", key, "SUCCESS", "SYSTEM", details);
            
        } catch (Exception e) {
            logger.error("Error recording action for key: {}, algorithm: {}", key, algorithm, e);
        }
    }
    
    /**
     * Get current rate limit status
     */
    public RateLimitStatus getStatus(String key, String rateLimitType) {
        RateLimitConfig config = getRateLimitConfig(rateLimitType);
        return getStatus(key, config.getLimit(), config.getDuration(), 
                        config.getTimeUnit(), config.getAlgorithm());
    }
    
    /**
     * Get current rate limit status with custom parameters
     */
    public RateLimitStatus getStatus(String key, int limit, int duration, TimeUnit timeUnit, RateLimitAlgorithm algorithm) {
        try {
            RateLimitResult result = isAllowed(key, limit, duration, timeUnit, algorithm);
            
            return new RateLimitStatus(
                key,
                algorithm,
                limit,
                result.getRemaining(),
                result.isAllowed(),
                LocalDateTime.now(),
                getResetTime(key, duration, timeUnit, algorithm)
            );
        } catch (Exception e) {
            logger.error("Error getting status for key: {}, algorithm: {}", key, algorithm, e);
            return new RateLimitStatus(key, algorithm, limit, limit, true, LocalDateTime.now(), LocalDateTime.now());
        }
    }
    
    /**
     * Get rate limit configuration for a specific type
     */
    private RateLimitConfig getRateLimitConfig(String rateLimitType) {
        switch (rateLimitType) {
            case LOGIN_ATTEMPTS:
                return new RateLimitConfig(
                    rateLimitProperties.getLoginAttempts().getLimit(),
                    rateLimitProperties.getLoginAttempts().getDuration(),
                    rateLimitProperties.getLoginAttempts().getUnit(),
                    RateLimitAlgorithm.valueOf(rateLimitProperties.getLoginAttempts().getAlgorithm())
                );
            case API_REQUESTS:
                return new RateLimitConfig(
                    rateLimitProperties.getApiRequests().getLimit(),
                    rateLimitProperties.getApiRequests().getDuration(),
                    rateLimitProperties.getApiRequests().getUnit(),
                    RateLimitAlgorithm.valueOf(rateLimitProperties.getApiRequests().getAlgorithm())
                );
            case OTP_VERIFICATION:
                return new RateLimitConfig(
                    rateLimitProperties.getOtpVerification().getLimit(),
                    rateLimitProperties.getOtpVerification().getDuration(),
                    rateLimitProperties.getOtpVerification().getUnit(),
                    RateLimitAlgorithm.valueOf(rateLimitProperties.getOtpVerification().getAlgorithm())
                );    
            case TOTP_VERIFICATION:
                return new RateLimitConfig(
                    rateLimitProperties.getTotpVerification().getLimit(),
                    rateLimitProperties.getTotpVerification().getDuration(),
                    rateLimitProperties.getTotpVerification().getUnit(),
                    RateLimitAlgorithm.valueOf(rateLimitProperties.getTotpVerification().getAlgorithm())
                );
            case ADMIN_ACTIONS:
                return new RateLimitConfig(
                    rateLimitProperties.getAdminActions().getLimit(),
                    rateLimitProperties.getAdminActions().getDuration(),
                    rateLimitProperties.getAdminActions().getUnit(),
                    RateLimitAlgorithm.valueOf(rateLimitProperties.getAdminActions().getAlgorithm())
                );
            default:
                // Default fallback configuration
                return new RateLimitConfig(
                    rateLimitProperties.getThreshold(),
                    15,
                    TimeUnit.MINUTES,
                    RateLimitAlgorithm.FIXED_WINDOW
                );
        }
    }
    
    /**
     * Reset rate limit for a specific key
     */
    public boolean resetRateLimit(String key, RateLimitAlgorithm algorithm) {
        try {
            String redisKey = getRateLimitKey(key, algorithm);
            Boolean deleted = redisTemplate.delete(redisKey);
            
            if (Boolean.TRUE.equals(deleted)) {
                Map<String, Object> details = new HashMap<>();
                details.put("key", key);
                details.put("algorithm", algorithm.name());
                
                securityAuditService.logAdminAction("SYSTEM", "RATE_LIMIT_RESET", key, "SUCCESS", "SYSTEM", details);
                
                logger.info("Rate limit reset for key: {}, algorithm: {}", key, algorithm);
                return true;
            }
            
            return false;
        } catch (Exception e) {
            logger.error("Error resetting rate limit for key: {}, algorithm: {}", key, algorithm, e);
            return false;
        }
    }
    
    /**
     * Get comprehensive rate limit statistics
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        try {
            // Get all rate limit keys
            Set<String> keys = redisTemplate.keys(RATE_LIMIT_PREFIX + "*");
            
            Map<RateLimitAlgorithm, Integer> algorithmCounts = new HashMap<>();
            int totalKeys = keys != null ? keys.size() : 0;
            int activeKeys = 0;
            
            if (keys != null) {
                for (String key : keys) {
                    // Count by algorithm
                    for (RateLimitAlgorithm algorithm : RateLimitAlgorithm.values()) {
                        if (key.contains(algorithm.name().toLowerCase())) {
                            algorithmCounts.merge(algorithm, 1, Integer::sum);
                        }
                    }
                    
                    // Check if key is active (has TTL)
                    Long ttl = redisTemplate.getExpire(key);
                    if (ttl != null && ttl > 0) {
                        activeKeys++;
                    }
                }
            }
            
            stats.put("totalKeys", totalKeys);
            stats.put("activeKeys", activeKeys);
            stats.put("algorithmDistribution", algorithmCounts);
            stats.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            
        } catch (Exception e) {
            logger.error("Error getting rate limiting statistics", e);
            stats.put("error", "Failed to retrieve statistics");
        }
        
        return stats;
    }
    
    // Private implementation methods
    
    private RateLimitResult checkFixedWindow(String key, int limit, int duration, TimeUnit timeUnit) {
        String redisKey = RATE_LIMIT_PREFIX + "fixed:" + key;
        
        // Lua script for atomic fixed window check
        String luaScript = 
            "local key = KEYS[1] " +
            "local limit = tonumber(ARGV[1]) " +
            "local duration = tonumber(ARGV[2]) " +
            "local current = redis.call('GET', key) " +
            "if current == false then " +
            "  return {1, limit - 1} " +
            "else " +
            "  current = tonumber(current) " +
            "  if current < limit then " +
            "    return {1, limit - current - 1} " +
            "  else " +
            "    return {0, 0} " +
            "  end " +
            "end";
        
        DefaultRedisScript<List> script = new DefaultRedisScript<>(luaScript, List.class);
        List<Object> result = redisTemplate.execute(script, 
            Collections.singletonList(redisKey), 
            String.valueOf(limit), 
            String.valueOf(timeUnit.toSeconds(duration)));
        
        if (result != null && result.size() == 2) {
            boolean allowed = "1".equals(String.valueOf(result.get(0)));
            int remaining = Integer.parseInt(String.valueOf(result.get(1)));
            return new RateLimitResult(allowed, remaining, limit, "Fixed window check", RateLimitAlgorithm.FIXED_WINDOW);
        }
        
        return new RateLimitResult(false, 0, limit, "Script execution failed", RateLimitAlgorithm.FIXED_WINDOW);
    }
    
    private RateLimitResult checkSlidingWindow(String key, int limit, int duration, TimeUnit timeUnit) {
        String redisKey = SLIDING_WINDOW_PREFIX + key;
        long windowSizeMs = timeUnit.toMillis(duration);
        long now = System.currentTimeMillis();
        long windowStart = now - windowSizeMs;
        
        // Lua script for atomic sliding window check
        String luaScript = 
            "local key = KEYS[1] " +
            "local limit = tonumber(ARGV[1]) " +
            "local windowStart = tonumber(ARGV[2]) " +
            "local now = tonumber(ARGV[3]) " +
            "local windowSize = tonumber(ARGV[4]) " +
            
            "redis.call('ZREMRANGEBYSCORE', key, 0, windowStart) " +
            "local current = redis.call('ZCARD', key) " +
            
            "if current < limit then " +
            "  return {1, limit - current - 1} " +
            "else " +
            "  return {0, 0} " +
            "end";
        
        DefaultRedisScript<List> script = new DefaultRedisScript<>(luaScript, List.class);
        List<Object> result = redisTemplate.execute(script,
            Collections.singletonList(redisKey),
            String.valueOf(limit),
            String.valueOf(windowStart),
            String.valueOf(now),
            String.valueOf(windowSizeMs));
        
        if (result != null && result.size() == 2) {
            boolean allowed = "1".equals(String.valueOf(result.get(0)));
            int remaining = Integer.parseInt(String.valueOf(result.get(1)));
            return new RateLimitResult(allowed, remaining, limit, "Sliding window check", RateLimitAlgorithm.SLIDING_WINDOW);
        }
        
        return new RateLimitResult(false, 0, limit, "Script execution failed", RateLimitAlgorithm.SLIDING_WINDOW);
    }
    
    private RateLimitResult checkTokenBucket(String key, int limit, int duration, TimeUnit timeUnit) {
        String redisKey = TOKEN_BUCKET_PREFIX + key;
        long now = System.currentTimeMillis();
        long refillIntervalMs = timeUnit.toMillis(duration);
        
        // Lua script for token bucket algorithm
        String luaScript = 
            "local key = KEYS[1] " +
            "local capacity = tonumber(ARGV[1]) " +
            "local refillRate = tonumber(ARGV[2]) " +
            "local refillInterval = tonumber(ARGV[3]) " +
            "local now = tonumber(ARGV[4]) " +
            
            "local bucket = redis.call('HMGET', key, 'tokens', 'lastRefill') " +
            "local tokens = tonumber(bucket[1]) or capacity " +
            "local lastRefill = tonumber(bucket[2]) or now " +
            
            "local timePassed = now - lastRefill " +
            "local tokensToAdd = math.floor(timePassed / refillInterval * refillRate) " +
            "tokens = math.min(capacity, tokens + tokensToAdd) " +
            
            "if tokens >= 1 then " +
            "  tokens = tokens - 1 " +
            "  redis.call('HMSET', key, 'tokens', tokens, 'lastRefill', now) " +
            "  redis.call('EXPIRE', key, refillInterval / 1000 * 2) " +
            "  return {1, tokens} " +
            "else " +
            "  redis.call('HMSET', key, 'tokens', tokens, 'lastRefill', now) " +
            "  redis.call('EXPIRE', key, refillInterval / 1000 * 2) " +
            "  return {0, 0} " +
            "end";
        
        DefaultRedisScript<List> script = new DefaultRedisScript<>(luaScript, List.class);
        List<Object> result = redisTemplate.execute(script,
            Collections.singletonList(redisKey),
            String.valueOf(limit),
            String.valueOf(1), // refill rate: 1 token per interval
            String.valueOf(refillIntervalMs),
            String.valueOf(now));
        
        if (result != null && result.size() == 2) {
            boolean allowed = "1".equals(String.valueOf(result.get(0)));
            int remaining = Integer.parseInt(String.valueOf(result.get(1)));
            return new RateLimitResult(allowed, remaining, limit, "Token bucket check", RateLimitAlgorithm.TOKEN_BUCKET);
        }
        
        return new RateLimitResult(false, 0, limit, "Script execution failed", RateLimitAlgorithm.TOKEN_BUCKET);
    }
    
    private RateLimitResult checkLeakyBucket(String key, int limit, int duration, TimeUnit timeUnit) {
        String redisKey = LEAKY_BUCKET_PREFIX + key;
        long now = System.currentTimeMillis();
        long leakIntervalMs = timeUnit.toMillis(duration) / limit; // leak rate
        
        // Lua script for leaky bucket algorithm
        String luaScript = 
            "local key = KEYS[1] " +
            "local capacity = tonumber(ARGV[1]) " +
            "local leakInterval = tonumber(ARGV[2]) " +
            "local now = tonumber(ARGV[3]) " +
            
            "local bucket = redis.call('HMGET', key, 'volume', 'lastLeak') " +
            "local volume = tonumber(bucket[1]) or 0 " +
            "local lastLeak = tonumber(bucket[2]) or now " +
            
            "local timePassed = now - lastLeak " +
            "local leaks = math.floor(timePassed / leakInterval) " +
            "volume = math.max(0, volume - leaks) " +
            
            "if volume < capacity then " +
            "  volume = volume + 1 " +
            "  redis.call('HMSET', key, 'volume', volume, 'lastLeak', now) " +
            "  redis.call('EXPIRE', key, capacity * leakInterval / 1000) " +
            "  return {1, capacity - volume} " +
            "else " +
            "  redis.call('HMSET', key, 'volume', volume, 'lastLeak', now) " +
            "  redis.call('EXPIRE', key, capacity * leakInterval / 1000) " +
            "  return {0, 0} " +
            "end";
        
        DefaultRedisScript<List> script = new DefaultRedisScript<>(luaScript, List.class);
        List<Object> result = redisTemplate.execute(script,
            Collections.singletonList(redisKey),
            String.valueOf(limit),
            String.valueOf(leakIntervalMs),
            String.valueOf(now));
        
        if (result != null && result.size() == 2) {
            boolean allowed = "1".equals(String.valueOf(result.get(0)));
            int remaining = Integer.parseInt(String.valueOf(result.get(1)));
            return new RateLimitResult(allowed, remaining, limit, "Leaky bucket check", RateLimitAlgorithm.LEAKY_BUCKET);
        }
        
        return new RateLimitResult(false, 0, limit, "Script execution failed", RateLimitAlgorithm.LEAKY_BUCKET);
    }
    
    private void recordFixedWindow(String key, int duration, TimeUnit timeUnit) {
        String redisKey = RATE_LIMIT_PREFIX + "fixed:" + key;
        redisTemplate.opsForValue().increment(redisKey);
        redisTemplate.expire(redisKey, duration, timeUnit);
    }
    
    private void recordSlidingWindow(String key, int duration, TimeUnit timeUnit) {
        String redisKey = SLIDING_WINDOW_PREFIX + key;
        long now = System.currentTimeMillis();
        redisTemplate.opsForZSet().add(redisKey, String.valueOf(now), now);
        redisTemplate.expire(redisKey, duration, timeUnit);
    }
    
    private void recordTokenBucket(String key, int limit, int duration, TimeUnit timeUnit) {
        // Token consumption is handled in the check method
    }
    
    private void recordLeakyBucket(String key, int limit, int duration, TimeUnit timeUnit) {
        // Request processing is handled in the check method
    }
    
    private String getRateLimitKey(String key, RateLimitAlgorithm algorithm) {
        return RATE_LIMIT_PREFIX + algorithm.name().toLowerCase() + ":" + key;
    }
    
    private LocalDateTime getResetTime(String key, int duration, TimeUnit timeUnit, RateLimitAlgorithm algorithm) {
        try {
            String redisKey = getRateLimitKey(key, algorithm);
            Long ttl = redisTemplate.getExpire(redisKey, TimeUnit.SECONDS);
            
            if (ttl != null && ttl > 0) {
                return LocalDateTime.now().plusSeconds(ttl);
            }
        } catch (Exception e) {
            logger.warn("Could not get reset time for key: {}", key, e);
        }
        
        return LocalDateTime.now().plus(duration, timeUnit.toChronoUnit());
    }
    
    // Data classes
    
    /**
     * Internal configuration class for rate limits
     */
    private static class RateLimitConfig {
        private final int limit;
        private final int duration;
        private final TimeUnit timeUnit;
        private final RateLimitAlgorithm algorithm;
        
        public RateLimitConfig(int limit, int duration, TimeUnit timeUnit, RateLimitAlgorithm algorithm) {
            this.limit = limit;
            this.duration = duration;
            this.timeUnit = timeUnit;
            this.algorithm = algorithm;
        }
        
        public int getLimit() { return limit; }
        public int getDuration() { return duration; }
        public TimeUnit getTimeUnit() { return timeUnit; }
        public RateLimitAlgorithm getAlgorithm() { return algorithm; }
    }
    
    public static class RateLimitResult {
        private final boolean allowed;
        private final int remaining;
        private final int limit;
        private final String message;
        private final RateLimitAlgorithm algorithm;
        
        public RateLimitResult(boolean allowed, int remaining, int limit, String message, RateLimitAlgorithm algorithm) {
            this.allowed = allowed;
            this.remaining = remaining;
            this.limit = limit;
            this.message = message;
            this.algorithm = algorithm;
        }
        
        public boolean isAllowed() { return allowed; }
        public int getRemaining() { return remaining; }
        public int getLimit() { return limit; }
        public String getMessage() { return message; }
        public RateLimitAlgorithm getAlgorithm() { return algorithm; }
    }
    
    public static class RateLimitStatus {
        private final String key;
        private final RateLimitAlgorithm algorithm;
        private final int limit;
        private final int remaining;
        private final boolean allowed;
        private final LocalDateTime checkTime;
        private final LocalDateTime resetTime;
        
        public RateLimitStatus(String key, RateLimitAlgorithm algorithm, int limit, int remaining, 
                              boolean allowed, LocalDateTime checkTime, LocalDateTime resetTime) {
            this.key = key;
            this.algorithm = algorithm;
            this.limit = limit;
            this.remaining = remaining;
            this.allowed = allowed;
            this.checkTime = checkTime;
            this.resetTime = resetTime;
        }
        
        public String getKey() { return key; }
        public RateLimitAlgorithm getAlgorithm() { return algorithm; }
        public int getLimit() { return limit; }
        public int getRemaining() { return remaining; }
        public boolean isAllowed() { return allowed; }
        public LocalDateTime getCheckTime() { return checkTime; }
        public LocalDateTime getResetTime() { return resetTime; }
    }
}