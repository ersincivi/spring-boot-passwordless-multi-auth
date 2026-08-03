package io.github.ersincivi.passwordless.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * Configuration properties for rate limiting settings
 */
@Component
@ConfigurationProperties(prefix = "app.rate-limit")
public class RateLimitProperties {
    
    private int threshold = 3;
    private LoginAttempts loginAttempts = new LoginAttempts();
    private ApiRequests apiRequests = new ApiRequests();
    private PasswordReset passwordReset = new PasswordReset();
    private OtpVerification otpVerification = new OtpVerification();
    private TotpVerification totpVerification = new TotpVerification();
    private AdminActions adminActions = new AdminActions();
    
    // Getters and setters
    public int getThreshold() { return threshold; }
    public void setThreshold(int threshold) { this.threshold = threshold; }
    
    public LoginAttempts getLoginAttempts() { return loginAttempts; }
    public void setLoginAttempts(LoginAttempts loginAttempts) { this.loginAttempts = loginAttempts; }
    
    public ApiRequests getApiRequests() { return apiRequests; }
    public void setApiRequests(ApiRequests apiRequests) { this.apiRequests = apiRequests; }
    
    public PasswordReset getPasswordReset() { return passwordReset; }
    public void setPasswordReset(PasswordReset passwordReset) { this.passwordReset = passwordReset; }
    
    public OtpVerification getOtpVerification() { return otpVerification; }
    public void setOtpVerification(OtpVerification otpVerification) { this.otpVerification = otpVerification; }

    public TotpVerification getTotpVerification() { return totpVerification; }
    public void setTotpVerification(TotpVerification totpVerification) { this.totpVerification = totpVerification; }
    
    public AdminActions getAdminActions() { return adminActions; }
    public void setAdminActions(AdminActions adminActions) { this.adminActions = adminActions; }
    
    // Inner classes for specific rate limit configurations
    public static class LoginAttempts {
        private int limit = 3;
        private int duration = 15;
        private TimeUnit unit = TimeUnit.MINUTES;
        private String algorithm = "FIXED_WINDOW";
        
        public int getLimit() { return limit; }
        public void setLimit(int limit) { this.limit = limit; }
        
        public int getDuration() { return duration; }
        public void setDuration(int duration) { this.duration = duration; }
        
        public TimeUnit getUnit() { return unit; }
        public void setUnit(TimeUnit unit) { this.unit = unit; }
        
        public String getAlgorithm() { return algorithm; }
        public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }
    }
    
    public static class ApiRequests {
        private int limit = 100;
        private int duration = 1;
        private TimeUnit unit = TimeUnit.HOURS;
        private String algorithm = "SLIDING_WINDOW";
        
        public int getLimit() { return limit; }
        public void setLimit(int limit) { this.limit = limit; }
        
        public int getDuration() { return duration; }
        public void setDuration(int duration) { this.duration = duration; }
        
        public TimeUnit getUnit() { return unit; }
        public void setUnit(TimeUnit unit) { this.unit = unit; }
        
        public String getAlgorithm() { return algorithm; }
        public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }
    }
    
    public static class PasswordReset {
        private int limit = 2;
        private int duration = 24;
        private TimeUnit unit = TimeUnit.HOURS;
        private String algorithm = "FIXED_WINDOW";
        
        public int getLimit() { return limit; }
        public void setLimit(int limit) { this.limit = limit; }
        
        public int getDuration() { return duration; }
        public void setDuration(int duration) { this.duration = duration; }
        
        public TimeUnit getUnit() { return unit; }
        public void setUnit(TimeUnit unit) { this.unit = unit; }
        
        public String getAlgorithm() { return algorithm; }
        public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }
    }

    public static class OtpVerification {
        private int limit = 3;
        private int duration = 5;
        private TimeUnit unit = TimeUnit.MINUTES;
        private String algorithm = "TOKEN_BUCKET";
        
        public int getLimit() { return limit; }
        public void setLimit(int limit) { this.limit = limit; }
        
        public int getDuration() { return duration; }
        public void setDuration(int duration) { this.duration = duration; }
        
        public TimeUnit getUnit() { return unit; }
        public void setUnit(TimeUnit unit) { this.unit = unit; }
        
        public String getAlgorithm() { return algorithm; }
        public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }
    }
    
    public static class TotpVerification {
        private int limit = 3;
        private int duration = 5;
        private TimeUnit unit = TimeUnit.MINUTES;
        private String algorithm = "TOKEN_BUCKET";
        
        public int getLimit() { return limit; }
        public void setLimit(int limit) { this.limit = limit; }
        
        public int getDuration() { return duration; }
        public void setDuration(int duration) { this.duration = duration; }
        
        public TimeUnit getUnit() { return unit; }
        public void setUnit(TimeUnit unit) { this.unit = unit; }
        
        public String getAlgorithm() { return algorithm; }
        public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }
    }
    
    public static class AdminActions {
        private int limit = 30;
        private int duration = 1;
        private TimeUnit unit = TimeUnit.HOURS;
        private String algorithm = "LEAKY_BUCKET";
        
        public int getLimit() { return limit; }
        public void setLimit(int limit) { this.limit = limit; }
        
        public int getDuration() { return duration; }
        public void setDuration(int duration) { this.duration = duration; }
        
        public TimeUnit getUnit() { return unit; }
        public void setUnit(TimeUnit unit) { this.unit = unit; }
        
        public String getAlgorithm() { return algorithm; }
        public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }
    }
}