package io.github.ersincivi.passwordless.service.security_test_endpoint;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.ersincivi.passwordless.service.SecurityAuditService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.InetAddress;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Comprehensive GeoIP Security Service for IP-based geolocation validation
 * Provides location detection, risk assessment, and suspicious activity monitoring
 */
@Profile("dev") // Security test harness - dev profile only
@Service
public class GeoIpSecurityService {
    
    private static final Logger logger = LoggerFactory.getLogger(GeoIpSecurityService.class);
    
    @Autowired
    private StringRedisTemplate redisTemplate;
    
    @Autowired
    private ObjectMapper objectMapper;
    
    @Autowired
    private SecurityAuditService securityAuditService;
    
    @Value("${app.geoip.database.path:/opt/geoip/GeoLite2-City.mmdb}")
    private String geoipDatabasePath;
    
    @Value("${app.geoip.enabled:true}")
    private boolean geoipEnabled;
    
    @Value("${app.geoip.cache.ttl:3600}")
    private int cacheTtlSeconds;
    
    // Redis key prefixes
    private static final String GEOIP_CACHE_PREFIX = "geoip_cache:";
    private static final String USER_LOCATIONS_PREFIX = "user_locations:";
    private static final String SUSPICIOUS_IPS_PREFIX = "suspicious_ips:";
    private static final String COUNTRY_STATS_PREFIX = "country_stats:";
    
    // Risk levels
    public enum RiskLevel {
        LOW(0, "Low risk location"),
        MEDIUM(1, "Medium risk location"), 
        HIGH(2, "High risk location"),
        CRITICAL(3, "Critical risk location");
        
        private final int level;
        private final String description;
        
        RiskLevel(int level, String description) {
            this.level = level;
            this.description = description;
        }
        
        public int getLevel() { return level; }
        public String getDescription() { return description; }
    }
    
    /**
     * Get geolocation information for an IP address
     */
    public GeoLocationResult getGeoLocation(String ipAddress) {
        if (!geoipEnabled || ipAddress == null || ipAddress.trim().isEmpty()) {
            return createEmptyResult(ipAddress, "GeoIP service disabled or invalid IP");
        }
        
        // Check cache first
        String cacheKey = GEOIP_CACHE_PREFIX + ipAddress;
        String cachedResult = redisTemplate.opsForValue().get(cacheKey);
        
        if (cachedResult != null) {
            try {
                GeoLocationResult result = objectMapper.readValue(cachedResult, GeoLocationResult.class);
                result.setCacheHit(true);
                return result;
            } catch (JsonProcessingException e) {
                logger.warn("Failed to deserialize cached geo location for IP: {}", ipAddress, e);
            }
        }
        
        // Perform geo lookup
        GeoLocationResult result = performGeoLookup(ipAddress);
        
        // Cache the result
        try {
            String resultJson = objectMapper.writeValueAsString(result);
            redisTemplate.opsForValue().set(cacheKey, resultJson, cacheTtlSeconds, TimeUnit.SECONDS);
        } catch (JsonProcessingException e) {
            logger.warn("Failed to cache geo location result for IP: {}", ipAddress, e);
        }
        
        return result;
    }
    
    /**
     * Validate login attempt based on geolocation
     */
    public GeoSecurityValidation validateLoginLocation(String username, String ipAddress, String userAgent) {
        try {
            GeoLocationResult geoResult = getGeoLocation(ipAddress);
            
            // Get user's previous locations
            List<UserLocationHistory> locationHistory = getUserLocationHistory(username);
            
            // Assess risk based on location and history
            RiskLevel riskLevel = assessLocationRisk(geoResult, locationHistory);
            
            // Create validation result
            GeoSecurityValidation validation = new GeoSecurityValidation(
                geoResult,
                riskLevel,
                isNewLocation(geoResult, locationHistory),
                isSuspiciousLocation(geoResult),
                calculateDistanceFromLastLogin(geoResult, locationHistory),
                getLocationRecommendation(riskLevel, geoResult)
            );
            
            // Record this login attempt location
            recordUserLocation(username, geoResult, userAgent, riskLevel);
            
            // Log security event based on risk level
            logGeoSecurityEvent(username, ipAddress, userAgent, validation);
            
            return validation;
            
        } catch (Exception e) {
            logger.error("Error validating login location for user: {}, IP: {}", username, ipAddress, e);
            return createFailsafeValidation(ipAddress);
        }
    }
    
    /**
     * Check if IP address is from a high-risk country/region
     */
    public boolean isHighRiskCountry(String countryCode) {
        // Configurable list of high-risk countries (example list)
        Set<String> highRiskCountries = Set.of(
            // This is just an example - configure based on your security requirements
            "XX", "ZZ" // Placeholder country codes
        );
        
        return countryCode != null && highRiskCountries.contains(countryCode.toUpperCase());
    }
    
    /**
     * Get comprehensive geolocation statistics
     */
    public Map<String, Object> getGeoLocationStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        try {
            // Get country statistics
            Set<String> countryKeys = redisTemplate.keys(COUNTRY_STATS_PREFIX + "*");
            Map<String, Integer> countryStats = new HashMap<>();
            
            if (countryKeys != null) {
                for (String key : countryKeys) {
                    String country = key.substring(COUNTRY_STATS_PREFIX.length());
                    String count = redisTemplate.opsForValue().get(key);
                    countryStats.put(country, count != null ? Integer.parseInt(count) : 0);
                }
            }
            
            // Get suspicious IPs count
            Set<String> suspiciousKeys = redisTemplate.keys(SUSPICIOUS_IPS_PREFIX + "*");
            int suspiciousIpsCount = suspiciousKeys != null ? suspiciousKeys.size() : 0;
            
            // Get cache statistics
            Set<String> cacheKeys = redisTemplate.keys(GEOIP_CACHE_PREFIX + "*");
            int cachedEntriesCount = cacheKeys != null ? cacheKeys.size() : 0;
            
            stats.put("countryStatistics", countryStats);
            stats.put("suspiciousIpsCount", suspiciousIpsCount);
            stats.put("cachedEntriesCount", cachedEntriesCount);
            stats.put("geoipEnabled", geoipEnabled);
            stats.put("databasePath", geoipDatabasePath);
            stats.put("cacheTtlSeconds", cacheTtlSeconds);
            stats.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            
        } catch (Exception e) {
            logger.error("Error getting geolocation statistics", e);
            stats.put("error", "Failed to retrieve statistics");
        }
        
        return stats;
    }
    
    /**
     * Mark IP as suspicious
     */
    public void markIpAsSuspicious(String ipAddress, String reason, String reportedBy) {
        try {
            String suspiciousKey = SUSPICIOUS_IPS_PREFIX + ipAddress;
            
            Map<String, Object> suspiciousInfo = new HashMap<>();
            suspiciousInfo.put("ipAddress", ipAddress);
            suspiciousInfo.put("reason", reason);
            suspiciousInfo.put("reportedBy", reportedBy);
            suspiciousInfo.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            suspiciousInfo.put("geoLocation", getGeoLocation(ipAddress));
            
            String suspiciousJson = objectMapper.writeValueAsString(suspiciousInfo);
            redisTemplate.opsForValue().set(suspiciousKey, suspiciousJson, 7, TimeUnit.DAYS); // Keep for 7 days
            
            // Log security violation
            Map<String, Object> details = new HashMap<>();
            details.put("ipAddress", ipAddress);
            details.put("reason", reason);
            details.put("reportedBy", reportedBy);
            
            securityAuditService.logSecurityViolation(
                reportedBy, "IP_MARKED_SUSPICIOUS", reason, ipAddress, "SYSTEM", details);
            
            logger.warn("IP marked as suspicious: {}, Reason: {}, Reported by: {}", ipAddress, reason, reportedBy);
            
        } catch (Exception e) {
            logger.error("Error marking IP as suspicious: {}", ipAddress, e);
        }
    }
    
    /**
     * Get user's location history
     */
    public List<UserLocationHistory> getUserLocationHistory(String username) {
        return getUserLocationHistory(username, 10); // Default to last 10 locations
    }
    
    /**
     * Get user's location history with limit
     */
    public List<UserLocationHistory> getUserLocationHistory(String username, int limit) {
        try {
            String userLocationsKey = USER_LOCATIONS_PREFIX + username;
            List<String> locationData = redisTemplate.opsForList().range(userLocationsKey, 0, limit - 1);
            
            List<UserLocationHistory> history = new ArrayList<>();
            
            if (locationData != null) {
                for (String data : locationData) {
                    try {
                        UserLocationHistory location = objectMapper.readValue(data, UserLocationHistory.class);
                        history.add(location);
                    } catch (JsonProcessingException e) {
                        logger.warn("Failed to deserialize user location history: {}", data, e);
                    }
                }
            }
            
            return history;
            
        } catch (Exception e) {
            logger.error("Error getting user location history for: {}", username, e);
            return new ArrayList<>();
        }
    }
    
    // Private helper methods
    
    private GeoLocationResult performGeoLookup(String ipAddress) {
        try {
            // For this demo, we'll simulate GeoIP lookup since MaxMind database is not available
            // In production, you would use MaxMind's GeoIP2 Java library
            
            InetAddress inetAddress = InetAddress.getByName(ipAddress);
            
            // Simulate geolocation based on IP patterns
            GeoLocationResult result = simulateGeoLookup(ipAddress);
            
            logger.debug("Geo lookup completed for IP: {}, Country: {}, City: {}", 
                        ipAddress, result.getCountryCode(), result.getCity());
            
            return result;
            
        } catch (Exception e) {
            logger.error("Error performing geo lookup for IP: {}", ipAddress, e);
            return createEmptyResult(ipAddress, "Geo lookup failed: " + e.getMessage());
        }
    }
    
    private GeoLocationResult simulateGeoLookup(String ipAddress) {
        // Simulation for demo purposes - replace with actual MaxMind GeoIP2 implementation
        if (ipAddress.startsWith("127.") || ipAddress.startsWith("192.168.") || ipAddress.startsWith("10.")) {
            return new GeoLocationResult(ipAddress, "LOCALHOST", "Local", "Local Network", "LAN", 
                                       0.0, 0.0, "Local", "Local ISP", false, "Local network address");
        }
        
        // Simulate different countries based on IP patterns
        if (ipAddress.startsWith("1.")) {
            return new GeoLocationResult(ipAddress, "US", "United States", "New York", "NY", 
                                       40.7128, -74.0060, "America/New_York", "Example ISP", false, "Simulated US location");
        } else if (ipAddress.startsWith("2.")) {
            return new GeoLocationResult(ipAddress, "GB", "United Kingdom", "London", "ENG", 
                                       51.5074, -0.1278, "Europe/London", "Example UK ISP", false, "Simulated UK location");
        } else if (ipAddress.startsWith("3.")) {
            return new GeoLocationResult(ipAddress, "DE", "Germany", "Berlin", "BE", 
                                       52.5200, 13.4050, "Europe/Berlin", "Example DE ISP", false, "Simulated German location");
        }
        
        // Default simulation
        return new GeoLocationResult(ipAddress, "UNKNOWN", "Unknown", "Unknown", "UNKNOWN", 
                                   0.0, 0.0, "UTC", "Unknown ISP", false, "Simulated unknown location");
    }
    
    private GeoLocationResult createEmptyResult(String ipAddress, String message) {
        return new GeoLocationResult(ipAddress, "UNKNOWN", "Unknown", "Unknown", "UNKNOWN", 
                                   0.0, 0.0, "UTC", "Unknown", false, message);
    }
    
    private RiskLevel assessLocationRisk(GeoLocationResult geoResult, List<UserLocationHistory> history) {
        // Basic risk assessment logic
        if (geoResult.getCountryCode().equals("UNKNOWN")) {
            return RiskLevel.HIGH;
        }
        
        if (isHighRiskCountry(geoResult.getCountryCode())) {
            return RiskLevel.CRITICAL;
        }
        
        if (isNewLocation(geoResult, history)) {
            double distance = calculateDistanceFromLastLogin(geoResult, history);
            
            if (distance > 5000) { // More than 5000 km from last login
                return RiskLevel.HIGH;
            } else if (distance > 1000) { // More than 1000 km
                return RiskLevel.MEDIUM;
            }
        }
        
        return RiskLevel.LOW;
    }
    
    private boolean isNewLocation(GeoLocationResult geoResult, List<UserLocationHistory> history) {
        if (history.isEmpty()) {
            return true;
        }
        
        // Check if this country/city combination has been seen before
        for (UserLocationHistory location : history) {
            if (location.getCountryCode().equals(geoResult.getCountryCode()) &&
                location.getCity().equals(geoResult.getCity())) {
                return false;
            }
        }
        
        return true;
    }
    
    private boolean isSuspiciousLocation(GeoLocationResult geoResult) {
        String suspiciousKey = SUSPICIOUS_IPS_PREFIX + geoResult.getIpAddress();
        return Boolean.TRUE.equals(redisTemplate.hasKey(suspiciousKey));
    }
    
    private double calculateDistanceFromLastLogin(GeoLocationResult current, List<UserLocationHistory> history) {
        if (history.isEmpty()) {
            return 0.0;
        }
        
        UserLocationHistory lastLocation = history.get(0); // Most recent
        return calculateDistance(current.getLatitude(), current.getLongitude(),
                               lastLocation.getLatitude(), lastLocation.getLongitude());
    }
    
    private double calculateDistance(double lat1, double lon1, double lat2, double lon2) {
        // Haversine formula for calculating distance between two points on Earth
        final int R = 6371; // Radius of Earth in km
        
        double latDistance = Math.toRadians(lat2 - lat1);
        double lonDistance = Math.toRadians(lon2 - lon1);
        double a = Math.sin(latDistance / 2) * Math.sin(latDistance / 2)
                + Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2))
                * Math.sin(lonDistance / 2) * Math.sin(lonDistance / 2);
        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        
        return R * c;
    }
    
    private String getLocationRecommendation(RiskLevel riskLevel, GeoLocationResult geoResult) {
        switch (riskLevel) {
            case CRITICAL:
                return "BLOCK: Critical risk location detected. Consider blocking this login attempt.";
            case HIGH:
                return "CHALLENGE: High risk location. Require additional authentication (2FA, email verification).";
            case MEDIUM:
                return "MONITOR: Medium risk location. Monitor for suspicious activity.";
            case LOW:
            default:
                return "ALLOW: Low risk location. Normal processing.";
        }
    }
    
    private void recordUserLocation(String username, GeoLocationResult geoResult, String userAgent, RiskLevel riskLevel) {
        try {
            UserLocationHistory locationHistory = new UserLocationHistory(
                geoResult.getIpAddress(),
                geoResult.getCountryCode(),
                geoResult.getCountry(),
                geoResult.getCity(),
                geoResult.getRegion(),
                geoResult.getLatitude(),
                geoResult.getLongitude(),
                LocalDateTime.now(),
                userAgent,
                riskLevel.name()
            );
            
            String userLocationsKey = USER_LOCATIONS_PREFIX + username;
            String locationJson = objectMapper.writeValueAsString(locationHistory);
            
            // Add to the front of the list (most recent first)
            redisTemplate.opsForList().leftPush(userLocationsKey, locationJson);
            
            // Keep only the last 50 locations
            redisTemplate.opsForList().trim(userLocationsKey, 0, 49);
            
            // Set expiration for the entire list
            redisTemplate.expire(userLocationsKey, 90, TimeUnit.DAYS);
            
            // Update country statistics
            String countryStatsKey = COUNTRY_STATS_PREFIX + geoResult.getCountryCode();
            redisTemplate.opsForValue().increment(countryStatsKey);
            redisTemplate.expire(countryStatsKey, 30, TimeUnit.DAYS);
            
        } catch (Exception e) {
            logger.error("Error recording user location for: {}", username, e);
        }
    }
    
    private void logGeoSecurityEvent(String username, String ipAddress, String userAgent, GeoSecurityValidation validation) {
        try {
            Map<String, Object> details = new HashMap<>();
            details.put("ipAddress", ipAddress);
            details.put("country", validation.getGeoResult().getCountryCode());
            details.put("city", validation.getGeoResult().getCity());
            details.put("riskLevel", validation.getRiskLevel().name());
            details.put("newLocation", validation.isNewLocation());
            details.put("suspicious", validation.isSuspiciousLocation());
            details.put("distance", validation.getDistanceFromLastLogin());
            details.put("recommendation", validation.getRecommendation());
            
            String eventType = validation.getRiskLevel() == RiskLevel.CRITICAL ? "GEO_CRITICAL_RISK" :
                              validation.getRiskLevel() == RiskLevel.HIGH ? "GEO_HIGH_RISK" :
                              "GEO_LOCATION_CHECK";
            
            if (validation.getRiskLevel().getLevel() >= RiskLevel.HIGH.getLevel()) {
                securityAuditService.logSecurityViolation(
                    username, eventType, "High risk geolocation detected", ipAddress, userAgent, details);
            } else {
                securityAuditService.logAuthenticationEvent(
                    username, eventType, "SUCCESS", ipAddress, userAgent, details);
            }
            
        } catch (Exception e) {
            logger.error("Error logging geo security event for user: {}", username, e);
        }
    }
    
    private GeoSecurityValidation createFailsafeValidation(String ipAddress) {
        GeoLocationResult emptyResult = createEmptyResult(ipAddress, "Validation service unavailable");
        return new GeoSecurityValidation(
            emptyResult, RiskLevel.MEDIUM, false, false, 0.0, 
            "Service unavailable - proceed with caution");
    }
    
    // Data classes
    
    public static class GeoLocationResult {
        private String ipAddress;
        private String countryCode;
        private String country;
        private String city;
        private String region;
        private double latitude;
        private double longitude;
        private String timezone;
        private String isp;
        private boolean cacheHit;
        private String message;
        
        public GeoLocationResult() {}
        
        public GeoLocationResult(String ipAddress, String countryCode, String country, String city, String region,
                               double latitude, double longitude, String timezone, String isp, boolean cacheHit, String message) {
            this.ipAddress = ipAddress;
            this.countryCode = countryCode;
            this.country = country;
            this.city = city;
            this.region = region;
            this.latitude = latitude;
            this.longitude = longitude;
            this.timezone = timezone;
            this.isp = isp;
            this.cacheHit = cacheHit;
            this.message = message;
        }
        
        // Getters and setters
        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
        
        public String getCountryCode() { return countryCode; }
        public void setCountryCode(String countryCode) { this.countryCode = countryCode; }
        
        public String getCountry() { return country; }
        public void setCountry(String country) { this.country = country; }
        
        public String getCity() { return city; }
        public void setCity(String city) { this.city = city; }
        
        public String getRegion() { return region; }
        public void setRegion(String region) { this.region = region; }
        
        public double getLatitude() { return latitude; }
        public void setLatitude(double latitude) { this.latitude = latitude; }
        
        public double getLongitude() { return longitude; }
        public void setLongitude(double longitude) { this.longitude = longitude; }
        
        public String getTimezone() { return timezone; }
        public void setTimezone(String timezone) { this.timezone = timezone; }
        
        public String getIsp() { return isp; }
        public void setIsp(String isp) { this.isp = isp; }
        
        public boolean isCacheHit() { return cacheHit; }
        public void setCacheHit(boolean cacheHit) { this.cacheHit = cacheHit; }
        
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
    }
    
    public static class GeoSecurityValidation {
        private GeoLocationResult geoResult;
        private RiskLevel riskLevel;
        private boolean newLocation;
        private boolean suspiciousLocation;
        private double distanceFromLastLogin;
        private String recommendation;
        
        public GeoSecurityValidation(GeoLocationResult geoResult, RiskLevel riskLevel, boolean newLocation,
                                   boolean suspiciousLocation, double distanceFromLastLogin, String recommendation) {
            this.geoResult = geoResult;
            this.riskLevel = riskLevel;
            this.newLocation = newLocation;
            this.suspiciousLocation = suspiciousLocation;
            this.distanceFromLastLogin = distanceFromLastLogin;
            this.recommendation = recommendation;
        }
        
        public GeoLocationResult getGeoResult() { return geoResult; }
        public RiskLevel getRiskLevel() { return riskLevel; }
        public boolean isNewLocation() { return newLocation; }
        public boolean isSuspiciousLocation() { return suspiciousLocation; }
        public double getDistanceFromLastLogin() { return distanceFromLastLogin; }
        public String getRecommendation() { return recommendation; }
    }
    
    public static class UserLocationHistory {
        private String ipAddress;
        private String countryCode;
        private String country;
        private String city;
        private String region;
        private double latitude;
        private double longitude;
        private LocalDateTime timestamp;
        private String userAgent;
        private String riskLevel;
        
        public UserLocationHistory() {}
        
        public UserLocationHistory(String ipAddress, String countryCode, String country, String city, String region,
                                 double latitude, double longitude, LocalDateTime timestamp, String userAgent, String riskLevel) {
            this.ipAddress = ipAddress;
            this.countryCode = countryCode;
            this.country = country;
            this.city = city;
            this.region = region;
            this.latitude = latitude;
            this.longitude = longitude;
            this.timestamp = timestamp;
            this.userAgent = userAgent;
            this.riskLevel = riskLevel;
        }
        
        // Getters and setters
        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
        
        public String getCountryCode() { return countryCode; }
        public void setCountryCode(String countryCode) { this.countryCode = countryCode; }
        
        public String getCountry() { return country; }
        public void setCountry(String country) { this.country = country; }
        
        public String getCity() { return city; }
        public void setCity(String city) { this.city = city; }
        
        public String getRegion() { return region; }
        public void setRegion(String region) { this.region = region; }
        
        public double getLatitude() { return latitude; }
        public void setLatitude(double latitude) { this.latitude = latitude; }
        
        public double getLongitude() { return longitude; }
        public void setLongitude(double longitude) { this.longitude = longitude; }
        
        public LocalDateTime getTimestamp() { return timestamp; }
        public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
        
        public String getUserAgent() { return userAgent; }
        public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
        
        public String getRiskLevel() { return riskLevel; }
        public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
    }
}