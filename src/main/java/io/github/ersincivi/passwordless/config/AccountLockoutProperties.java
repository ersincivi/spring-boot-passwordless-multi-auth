package io.github.ersincivi.passwordless.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for account lockout settings
 */
@Component
@ConfigurationProperties(prefix = "app.account-lockout")
public class AccountLockoutProperties {
    
    private int maxFailedAttempts = 10;
    private int lockoutDurationMinutes = 30;
    private int attemptWindowMinutes = 15;
    
    public int getMaxFailedAttempts() {
        return maxFailedAttempts;
    }
    
    public void setMaxFailedAttempts(int maxFailedAttempts) {
        this.maxFailedAttempts = maxFailedAttempts;
    }
    
    public int getLockoutDurationMinutes() {
        return lockoutDurationMinutes;
    }
    
    public void setLockoutDurationMinutes(int lockoutDurationMinutes) {
        this.lockoutDurationMinutes = lockoutDurationMinutes;
    }
    
    public int getAttemptWindowMinutes() {
        return attemptWindowMinutes;
    }
    
    public void setAttemptWindowMinutes(int attemptWindowMinutes) {
        this.attemptWindowMinutes = attemptWindowMinutes;
    }
}