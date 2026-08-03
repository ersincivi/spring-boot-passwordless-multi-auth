package io.github.ersincivi.passwordless.service.security_test_endpoint;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.ersincivi.passwordless.service.SecurityAuditService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Comprehensive IDOR Security Service
 * Provides detection and testing for Insecure Direct Object Reference attacks
 */
@Profile("dev") // Security test harness - dev profile only
@Service
public class IdorSecurityService {

    private static final String IDOR_STATS_KEY = "idor:statistics";

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Autowired
    private SecurityAuditService securityAuditService;

    @Autowired
    private ObjectMapper objectMapper;

    // IDOR attack patterns
    private static final List<Pattern> IDOR_PATTERNS = Arrays.asList(
        // Numeric ID manipulation
        Pattern.compile("\\bid=\\d+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\buser_?id=\\d+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\baccount_?id=\\d+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bdocument_?id=\\d+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bfile_?id=\\d+", Pattern.CASE_INSENSITIVE),
        
        // UUID manipulation
        Pattern.compile("\\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", Pattern.CASE_INSENSITIVE),
        
        // Base64 encoded IDs
        Pattern.compile("\\b[A-Za-z0-9+/]{8,}={0,2}\\b"),
        
        // Sequential access attempts
        Pattern.compile("/users?/\\d+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("/profiles?/\\d+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("/documents?/\\d+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("/files?/\\d+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("/orders?/\\d+", Pattern.CASE_INSENSITIVE),
        
        // API endpoint enumeration
        Pattern.compile("/api/v\\d+/[^/]+/\\d+", Pattern.CASE_INSENSITIVE),
        
        // Admin/privileged resource access
        Pattern.compile("/admin/users?/\\d+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("/management/\\w+/\\d+", Pattern.CASE_INSENSITIVE),
        
        // File path traversal with IDs
        Pattern.compile("\\.\\..*\\d+", Pattern.CASE_INSENSITIVE),
        
        // Database record enumeration
        Pattern.compile("record_?id=\\d+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("row_?id=\\d+", Pattern.CASE_INSENSITIVE)
    );

    // Sensitive resource patterns that should have access control
    private static final Set<String> SENSITIVE_RESOURCES = Set.of(
        "user", "profile", "account", "document", "file", "order", 
        "payment", "transaction", "admin", "management", "config",
        "report", "audit", "log", "backup", "export"
    );

    /**
     * Analyze request for IDOR vulnerabilities
     */
    public Map<String, Object> analyzeRequest(HttpServletRequest request, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        List<String> detectedPatterns = new ArrayList<>();
        List<String> vulnerabilities = new ArrayList<>();
        int riskScore = 0;
        
        try {
            String requestURI = request.getRequestURI();
            String queryString = request.getQueryString();
            String userAgent = request.getHeader("User-Agent");
            String referer = request.getHeader("Referer");
            
            String fullRequest = requestURI + (queryString != null ? "?" + queryString : "");
            
            // Check for IDOR patterns in URL
            for (Pattern pattern : IDOR_PATTERNS) {
                if (pattern.matcher(fullRequest).find()) {
                    detectedPatterns.add(pattern.pattern());
                    riskScore += 2;
                }
            }
            
            // Check for sensitive resource access
            String lowerURI = requestURI.toLowerCase();
            for (String resource : SENSITIVE_RESOURCES) {
                if (lowerURI.contains(resource)) {
                    riskScore += 1;
                    vulnerabilities.add("Access to sensitive resource: " + resource);
                }
            }
            
            // Check for sequential access patterns (potential enumeration)
            if (isSequentialAccess(fullRequest)) {
                riskScore += 3;
                vulnerabilities.add("Sequential resource access detected (potential enumeration)");
            }
            
            // Check for privilege escalation attempts
            if (isPrivilegeEscalation(fullRequest)) {
                riskScore += 4;
                vulnerabilities.add("Privilege escalation attempt detected");
            }
            
            // Check for unauthorized access patterns
            if (isUnauthorizedAccess(fullRequest, userAgent)) {
                riskScore += 3;
                vulnerabilities.add("Unauthorized access pattern detected");
            }
            
            boolean isVulnerable = riskScore >= 3;
            String riskLevel = calculateRiskLevel(riskScore);
            
            result.put("isVulnerable", isVulnerable);
            result.put("riskScore", Math.min(riskScore, 10));
            result.put("riskLevel", riskLevel);
            result.put("requestURI", requestURI);
            result.put("queryString", queryString);
            result.put("detectedPatterns", detectedPatterns);
            result.put("vulnerabilities", vulnerabilities);
            result.put("recommendation", generateRecommendation(riskLevel, vulnerabilities));
            result.put("timestamp", LocalDateTime.now().toString());
            
            updateStatistics(isVulnerable, riskLevel, ipAddress);
            
        } catch (Exception e) {
            result.put("error", "IDOR analysis failed: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * Test specific IDOR payload
     */
    public Map<String, Object> testIdorPayload(String resourceUrl, String originalId, String testId, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            List<String> detectedPatterns = new ArrayList<>();
            List<String> attackTypes = new ArrayList<>();
            int riskScore = 0;
            
            String testUrl = resourceUrl.replace(originalId, testId);
            
            // Analyze the test URL for IDOR patterns
            for (Pattern pattern : IDOR_PATTERNS) {
                if (pattern.matcher(testUrl).find()) {
                    detectedPatterns.add(pattern.pattern());
                    riskScore += 2;
                }
            }
            
            // Categorize attack types
            if (isNumericIdManipulation(originalId, testId)) {
                attackTypes.add("Numeric ID Manipulation");
                riskScore += 3;
            }
            if (isUuidManipulation(originalId, testId)) {
                attackTypes.add("UUID Manipulation");
                riskScore += 2;
            }
            if (isSequentialEnumeration(originalId, testId)) {
                attackTypes.add("Sequential Enumeration");
                riskScore += 4;
            }
            if (isPrivilegeEscalationAttempt(testUrl)) {
                attackTypes.add("Privilege Escalation");
                riskScore += 5;
            }
            if (isBase64IdManipulation(originalId, testId)) {
                attackTypes.add("Base64 ID Manipulation");
                riskScore += 3;
            }
            
            boolean isBlocked = riskScore >= 3;
            String riskLevel = calculateRiskLevel(riskScore);
            
            result.put("originalId", originalId);
            result.put("testId", testId);
            result.put("originalUrl", resourceUrl);
            result.put("testUrl", testUrl);
            result.put("isBlocked", isBlocked);
            result.put("riskScore", Math.min(riskScore, 10));
            result.put("riskLevel", riskLevel);
            result.put("detectedPatterns", detectedPatterns);
            result.put("attackTypes", attackTypes);
            result.put("recommendation", generatePayloadRecommendation(riskLevel, attackTypes));
            
        } catch (Exception e) {
            result.put("error", "IDOR payload test failed: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * Perform comprehensive IDOR testing
     */
    public Map<String, Object> performComprehensiveTest(String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        List<Map<String, Object>> testResults = new ArrayList<>();
        
        // Comprehensive IDOR test scenarios
        Object[][] testScenarios = {
            {"/api/users/123", "123", "124"},        // Sequential ID manipulation
            {"/api/users/123", "123", "1"},          // Privilege escalation (admin user)
            {"/api/documents/456", "456", "999"},     // High-value ID access
            {"/api/profiles/789", "789", "000"},      // System account access
            {"/files/user-123.pdf", "123", "456"},   // File access manipulation
            {"/admin/users/123", "123", "124"},       // Admin endpoint access
            {"/api/orders/uuid-123", "uuid-123", "uuid-456"}, // UUID manipulation
            {"/api/accounts/base64abc", "base64abc", "base64xyz"}, // Base64 ID manipulation
            {"/management/reports/100", "100", "101"}, // Management resource access
            {"/api/transactions/12345", "12345", "99999"} // Financial data access
        };
        
        int totalTests = testScenarios.length;
        int blockedCount = 0;
        
        for (int i = 0; i < testScenarios.length; i++) {
            Object[] testData = testScenarios[i];
            String resourceUrl = (String) testData[0];
            String originalId = (String) testData[1];
            String testId = (String) testData[2];
            
            Map<String, Object> testResult = testIdorPayload(resourceUrl, originalId, testId, ipAddress);
            testResult.put("testId", "IDOR_" + (i + 1));
            testResult.put("testName", getTestName(i));
            testResults.add(testResult);
            
            if ((Boolean) testResult.get("isBlocked")) {
                blockedCount++;
            }
        }
        
        double protectionRate = (double) blockedCount / totalTests * 100;
        String effectivenessLevel = getEffectivenessLevel(protectionRate);
        
        result.put("totalTests", totalTests);
        result.put("blockedAttacks", blockedCount);
        result.put("protectionRate", String.format("%.1f%%", protectionRate));
        result.put("effectivenessLevel", effectivenessLevel);
        result.put("testResults", testResults);
        result.put("timestamp", LocalDateTime.now().toString());
        result.put("recommendation", generateComprehensiveRecommendation(protectionRate));
        
        return result;
    }

    /**
     * Validate access control for resource
     */
    public Map<String, Object> validateResourceAccess(String resourceUrl, String userId, String requestedResourceId, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            boolean isAuthorized = isUserAuthorizedForResource(userId, requestedResourceId);
            boolean isSensitiveResource = isSensitiveResource(resourceUrl);
            boolean hasProperAccess = hasProperAccessControl(resourceUrl);
            
            String accessLevel = determineAccessLevel(resourceUrl, userId);
            String recommendation;
            String action;
            
            if (isAuthorized && hasProperAccess) {
                recommendation = "Access granted - proper authorization confirmed";
                action = "ALLOW";
            } else if (!isAuthorized) {
                recommendation = "BLOCKED: User not authorized for requested resource";
                action = "BLOCK";
            } else if (!hasProperAccess) {
                recommendation = "WARNING: Resource lacks proper access control";
                action = "VALIDATE";
            } else {
                recommendation = "Access denied - insufficient permissions";
                action = "DENY";
            }
            
            result.put("resourceUrl", resourceUrl);
            result.put("userId", userId);
            result.put("requestedResourceId", requestedResourceId);
            result.put("isAuthorized", isAuthorized);
            result.put("isSensitiveResource", isSensitiveResource);
            result.put("hasProperAccess", hasProperAccess);
            result.put("accessLevel", accessLevel);
            result.put("recommendation", recommendation);
            result.put("action", action);
            result.put("timestamp", LocalDateTime.now().toString());
            
        } catch (Exception e) {
            result.put("error", "Resource access validation failed: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * Get IDOR statistics
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        try {
            String statsJson = redisTemplate.opsForValue().get(IDOR_STATS_KEY);
            if (statsJson != null) {
                stats = objectMapper.readValue(statsJson, Map.class);
            }
        } catch (Exception e) {
            stats.put("error", "Failed to retrieve statistics");
        }
        
        stats.putIfAbsent("totalAnalyses", 0);
        stats.putIfAbsent("vulnerableRequests", 0);
        stats.putIfAbsent("blockedRequests", 0);
        stats.putIfAbsent("lastUpdated", LocalDateTime.now().toString());
        
        return stats;
    }

    // Private helper methods
    private boolean isSequentialAccess(String request) {
        // Check for patterns indicating sequential access (enumeration)
        return request.matches(".*/\\d+$") && 
               (request.contains("user") || request.contains("document") || 
                request.contains("file") || request.contains("order"));
    }

    private boolean isPrivilegeEscalation(String request) {
        String lowerRequest = request.toLowerCase();
        return lowerRequest.contains("admin") || lowerRequest.contains("root") || 
               lowerRequest.contains("management") || lowerRequest.contains("config") ||
               request.matches(".*/[01]$"); // Accessing ID 0 or 1 (often admin)
    }

    private boolean isUnauthorizedAccess(String request, String userAgent) {
        // Check for automated tools or suspicious patterns
        return (userAgent != null && 
                (userAgent.toLowerCase().contains("bot") || 
                 userAgent.toLowerCase().contains("scanner") ||
                 userAgent.length() < 10)) ||
               request.matches(".*\\d{4,}.*"); // Very high ID numbers
    }

    private boolean isNumericIdManipulation(String original, String test) {
        try {
            int originalId = Integer.parseInt(original);
            int testId = Integer.parseInt(test);
            return originalId != testId;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private boolean isUuidManipulation(String original, String test) {
        return original.matches("[0-9a-f-]{36}") && test.matches("[0-9a-f-]{36}") && !original.equals(test);
    }

    private boolean isSequentialEnumeration(String original, String test) {
        try {
            int originalId = Integer.parseInt(original);
            int testId = Integer.parseInt(test);
            return Math.abs(testId - originalId) <= 10; // Sequential access within range
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private boolean isPrivilegeEscalationAttempt(String testUrl) {
        String lowerUrl = testUrl.toLowerCase();
        return lowerUrl.contains("admin") || lowerUrl.contains("root") || 
               lowerUrl.matches(".*/[01]$");
    }

    private boolean isBase64IdManipulation(String original, String test) {
        return original.matches("[A-Za-z0-9+/=]+") && test.matches("[A-Za-z0-9+/=]+") && 
               !original.equals(test) && original.length() >= 8;
    }

    private boolean isUserAuthorizedForResource(String userId, String resourceId) {
        // Simulate authorization check - in real implementation, check database/ACL
        return userId.equals(resourceId) || userId.equals("admin");
    }

    private boolean isSensitiveResource(String resourceUrl) {
        String lowerUrl = resourceUrl.toLowerCase();
        return SENSITIVE_RESOURCES.stream().anyMatch(lowerUrl::contains);
    }

    private boolean hasProperAccessControl(String resourceUrl) {
        // Simulate access control check - in real implementation, verify ACL
        return !resourceUrl.toLowerCase().contains("admin") || 
               resourceUrl.toLowerCase().contains("auth");
    }

    private String determineAccessLevel(String resourceUrl, String userId) {
        if (resourceUrl.toLowerCase().contains("admin")) {
            return "ADMIN";
        } else if (resourceUrl.toLowerCase().contains("user")) {
            return "USER";
        } else if (resourceUrl.toLowerCase().contains("public")) {
            return "PUBLIC";
        }
        return "RESTRICTED";
    }

    private String calculateRiskLevel(int riskScore) {
        if (riskScore >= 8) return "CRITICAL";
        if (riskScore >= 6) return "HIGH";
        if (riskScore >= 4) return "MEDIUM";
        if (riskScore >= 2) return "LOW";
        return "MINIMAL";
    }

    private String getEffectivenessLevel(double protectionRate) {
        if (protectionRate >= 90) return "EXCELLENT";
        if (protectionRate >= 75) return "GOOD";
        if (protectionRate >= 50) return "FAIR";
        return "POOR";
    }

    private String getTestName(int index) {
        String[] testNames = {
            "Sequential ID Manipulation",
            "Privilege Escalation (Admin Access)",
            "High-Value ID Access",
            "System Account Access", 
            "File Access Manipulation",
            "Admin Endpoint Access",
            "UUID Manipulation",
            "Base64 ID Manipulation",
            "Management Resource Access",
            "Financial Data Access"
        };
        return index < testNames.length ? testNames[index] : "Unknown IDOR Test";
    }

    private String generateRecommendation(String riskLevel, List<String> vulnerabilities) {
        StringBuilder rec = new StringBuilder();
        
        switch (riskLevel) {
            case "CRITICAL":
                rec.append("IMMEDIATE ACTION: Critical IDOR vulnerability detected. ");
                break;
            case "HIGH":
                rec.append("HIGH PRIORITY: IDOR attack patterns found. ");
                break;
            case "MEDIUM":
                rec.append("MEDIUM PRIORITY: Potential IDOR vulnerability. ");
                break;
            default:
                rec.append("Monitor for IDOR access patterns. ");
        }
        
        if (vulnerabilities.stream().anyMatch(v -> v.contains("sensitive resource"))) {
            rec.append("Implement proper access controls for sensitive resources. ");
        }
        if (vulnerabilities.stream().anyMatch(v -> v.contains("enumeration"))) {
            rec.append("Block sequential enumeration attempts. ");
        }
        if (vulnerabilities.stream().anyMatch(v -> v.contains("escalation"))) {
            rec.append("Prevent privilege escalation through ID manipulation. ");
        }
        
        return rec.toString();
    }

    private String generatePayloadRecommendation(String riskLevel, List<String> attackTypes) {
        StringBuilder rec = new StringBuilder("Detected IDOR attempt. ");
        
        if (attackTypes.contains("Numeric ID Manipulation")) {
            rec.append("Use random, non-sequential identifiers. ");
        }
        if (attackTypes.contains("Privilege Escalation")) {
            rec.append("Implement role-based access control. ");
        }
        if (attackTypes.contains("Sequential Enumeration")) {
            rec.append("Add rate limiting and access logging. ");
        }
        
        rec.append("Validate user authorization for each resource access.");
        return rec.toString();
    }

    private String generateComprehensiveRecommendation(double protectionRate) {
        if (protectionRate >= 90) {
            return "EXCELLENT: IDOR protection is highly effective against direct object reference attacks.";
        } else if (protectionRate >= 75) {
            return "GOOD: IDOR protection is generally effective but some enumeration may succeed.";
        } else if (protectionRate >= 50) {
            return "FAIR: IDOR protection needs improvement for access control.";
        } else {
            return "CRITICAL: IDOR protection is insufficient against direct object reference attacks.";
        }
    }

    private void updateStatistics(boolean vulnerable, String riskLevel, String ipAddress) {
        try {
            Map<String, Object> stats = getStatistics();
            
            int totalAnalyses = (Integer) stats.getOrDefault("totalAnalyses", 0) + 1;
            int vulnerableRequests = (Integer) stats.getOrDefault("vulnerableRequests", 0);
            int blockedRequests = (Integer) stats.getOrDefault("blockedRequests", 0);
            
            if (vulnerable) {
                vulnerableRequests++;
                blockedRequests++; // Our system blocks vulnerable requests
            }
            
            stats.put("totalAnalyses", totalAnalyses);
            stats.put("vulnerableRequests", vulnerableRequests);
            stats.put("blockedRequests", blockedRequests);
            stats.put("protectionRate", String.format("%.1f%%", (double) blockedRequests / totalAnalyses * 100));
            stats.put("lastRiskLevel", riskLevel);
            stats.put("lastUpdated", LocalDateTime.now().toString());
            
            String statsJson = objectMapper.writeValueAsString(stats);
            redisTemplate.opsForValue().set(IDOR_STATS_KEY, statsJson, 24, TimeUnit.HOURS);
            
        } catch (Exception e) {
            // Log error but continue
        }
    }
}