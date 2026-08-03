package io.github.ersincivi.passwordless.service;

import io.github.ersincivi.passwordless.config.AccountLockoutProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.TimeUnit;

/**
 * Service for managing account lockout functionality to prevent brute force attacks
 */
@Service
public class AccountLockoutService {
    
    @Autowired
    private StringRedisTemplate redisTemplate;
    
    @Autowired
    private AccountLockoutProperties lockoutProperties;
    
    // Redis key prefixes
    private static final String FAILED_ATTEMPTS_KEY = "failed_attempts:";
    private static final String LOCKOUT_KEY = "account_locked:";
    private static final String LOCKOUT_TIME_KEY = "lockout_time:";
    
    /**
     * Record a failed login attempt for a username
     */
    public void recordFailedAttempt(String username) {
        if (username == null || username.trim().isEmpty()) {
            return;
        }
        
        String attemptsKey = FAILED_ATTEMPTS_KEY + username.toLowerCase();
        
        // Increment failed attempts counter
        Long attempts = redisTemplate.opsForValue().increment(attemptsKey);
        
        // Set expiration for the attempts counter (reset window)
        if (attempts != null &&  attempts == 1) {
            redisTemplate.expire(attemptsKey, lockoutProperties.getAttemptWindowMinutes(), TimeUnit.MINUTES);
        }
        
        // Lock account if max attempts reached
        if (attempts != null && attempts >= lockoutProperties.getMaxFailedAttempts()) {
            lockAccount(username);
        }
    }
    
    /**
     * Clear failed attempts for a username (called on successful login)
     */
    public void clearFailedAttempts(String username) {
        if (username == null || username.trim().isEmpty()) {
            return;
        }
        
        String attemptsKey = FAILED_ATTEMPTS_KEY + username.toLowerCase();
        redisTemplate.delete(attemptsKey);
    }
    
    /**
     * Check if an account is currently locked
     */
    public boolean isAccountLocked(String username) {
        if (username == null || username.trim().isEmpty()) {
            return false;
        }
        
        String lockKey = LOCKOUT_KEY + username.toLowerCase();
        return Boolean.TRUE.equals(redisTemplate.hasKey(lockKey));
    }
    
    /**
     * Lock an account for the specified duration
     */
    public void lockAccount(String username) {
        if (username == null || username.trim().isEmpty()) {
            return;
        }
        
        String lockKey = LOCKOUT_KEY + username.toLowerCase();
        String timeKey = LOCKOUT_TIME_KEY + username.toLowerCase();
        String lockTime = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        
        // Set lockout flag
        redisTemplate.opsForValue().set(lockKey, "true", lockoutProperties.getLockoutDurationMinutes(), TimeUnit.MINUTES);
        
        // Store lockout time for reference
        redisTemplate.opsForValue().set(timeKey, lockTime, lockoutProperties.getLockoutDurationMinutes(), TimeUnit.MINUTES);
        
        // Clear failed attempts counter since account is now locked
        clearFailedAttempts(username);
    }
    
    /**
     * Manually unlock an account (admin function)
     */
    public void unlockAccount(String username) {
        if (username == null || username.trim().isEmpty()) {
            return;
        }
        
        String lockKey = LOCKOUT_KEY + username.toLowerCase();
        String timeKey = LOCKOUT_TIME_KEY + username.toLowerCase();
        String attemptsKey = FAILED_ATTEMPTS_KEY + username.toLowerCase();
        
        redisTemplate.delete(lockKey);
        redisTemplate.delete(timeKey);
        redisTemplate.delete(attemptsKey);
    }
    
    /**
     * Get the number of failed attempts for a username
     */
    public int getFailedAttempts(String username) {
        if (username == null || username.trim().isEmpty()) {
            return 0;
        }
        
        String attemptsKey = FAILED_ATTEMPTS_KEY + username.toLowerCase();
        String attempts = redisTemplate.opsForValue().get(attemptsKey);
        return attempts != null ? Integer.parseInt(attempts) : 0;
    }
    
    /**
     * Get remaining time until account unlock (in minutes)
     */
    public long getRemainingLockoutTime(String username) {
        if (username == null || username.trim().isEmpty() || !isAccountLocked(username)) {
            return 0;
        }
        
        String lockKey = LOCKOUT_KEY + username.toLowerCase();
        Long ttl = redisTemplate.getExpire(lockKey, TimeUnit.MINUTES);
        return ttl != null ? ttl : 0;
    }
    
    /**
     * Get lockout information for an account
     */
    public AccountLockoutInfo getLockoutInfo(String username) {
        if (username == null || username.trim().isEmpty()) {
            return new AccountLockoutInfo(false, 0, 0, null);
        }
        
        boolean isLocked = isAccountLocked(username);
        int failedAttempts = getFailedAttempts(username);
        long remainingTime = getRemainingLockoutTime(username);
        
        String lockTime = null;
        if (isLocked) {
            String timeKey = LOCKOUT_TIME_KEY + username.toLowerCase();
            lockTime = redisTemplate.opsForValue().get(timeKey);
        }
        
        return new AccountLockoutInfo(isLocked, failedAttempts, remainingTime, lockTime);
    }
    
    /**
     * Get remaining attempts before lockout
     */
    public int getRemainingAttempts(String username) {
        int failedAttempts = getFailedAttempts(username);
        return Math.max(0, lockoutProperties.getMaxFailedAttempts() - failedAttempts);
    }
    
    /**
     * Check if the next failed attempt will trigger a lockout
     */
    public boolean willNextAttemptLockAccount(String username) {
        return getFailedAttempts(username) >= (lockoutProperties.getMaxFailedAttempts() - 1);
    }
    
    // Configuration getters
    public int getMaxFailedAttempts() {
        return lockoutProperties.getMaxFailedAttempts();
    }
    
    public int getLockoutDurationMinutes() {
        return lockoutProperties.getLockoutDurationMinutes();
    }
    
    public int getAttemptWindowMinutes() {
        return lockoutProperties.getAttemptWindowMinutes();
    }
    
    /**
     * Account lockout information data class
     */
    public static class AccountLockoutInfo {
        private final boolean locked;
        private final int failedAttempts;
        private final long remainingLockoutMinutes;
        private final String lockoutTime;
        
        public AccountLockoutInfo(boolean locked, int failedAttempts, long remainingLockoutMinutes, String lockoutTime) {
            this.locked = locked;
            this.failedAttempts = failedAttempts;
            this.remainingLockoutMinutes = remainingLockoutMinutes;
            this.lockoutTime = lockoutTime;
        }
        
        public boolean isLocked() {
            return locked;
        }
        
        public int getFailedAttempts() {
            return failedAttempts;
        }
        
        public long getRemainingLockoutMinutes() {
            return remainingLockoutMinutes;
        }
        
        public String getLockoutTime() {
            return lockoutTime;
        }
    }
}