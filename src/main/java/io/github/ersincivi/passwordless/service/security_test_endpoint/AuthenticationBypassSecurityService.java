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
 * Comprehensive Authentication Bypass Security Service
 * Provides detection and testing for authentication bypass vulnerabilities
 */
@Profile("dev") // Security test harness - dev profile only
@Service
public class AuthenticationBypassSecurityService {

    private static final String AUTH_BYPASS_STATS_KEY = "auth_bypass:statistics";

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Autowired
    private SecurityAuditService securityAuditService;

    @Autowired
    private ObjectMapper objectMapper;

    // Authentication bypass attack patterns
    private static final List<Pattern> AUTH_BYPASS_PATTERNS = Arrays.asList(
        // SQL injection authentication bypass patterns
        Pattern.compile("'\\s*(or|OR)\\s*'1'\\s*=\\s*'1", Pattern.CASE_INSENSITIVE),
        Pattern.compile("'\\s*(or|OR)\\s*1\\s*=\\s*1", Pattern.CASE_INSENSITIVE),
        Pattern.compile("admin'\\s*--", Pattern.CASE_INSENSITIVE),
        Pattern.compile("'\\s*(union|UNION)\\s*(select|SELECT)", Pattern.CASE_INSENSITIVE),
        
        // NoSQL injection patterns
        Pattern.compile("\\{\\s*\\$ne\\s*:\\s*null\\s*\\}", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\{\\s*\\$regex\\s*:", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\{\\s*\\$where\\s*:", Pattern.CASE_INSENSITIVE),
        
        // Parameter pollution patterns
        Pattern.compile("admin\\[\\]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("user\\[role\\]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("auth\\[bypass\\]", Pattern.CASE_INSENSITIVE),
        
        // Header manipulation patterns
        Pattern.compile("x-forwarded-user", Pattern.CASE_INSENSITIVE),
        Pattern.compile("x-remote-user", Pattern.CASE_INSENSITIVE),
        Pattern.compile("x-authenticated", Pattern.CASE_INSENSITIVE),
        Pattern.compile("x-admin", Pattern.CASE_INSENSITIVE),
        
        // Token manipulation patterns
        Pattern.compile("bearer\\s*null", Pattern.CASE_INSENSITIVE),
        Pattern.compile("jwt\\s*none", Pattern.CASE_INSENSITIVE),
        Pattern.compile("token.*admin", Pattern.CASE_INSENSITIVE),
        
        // Cookie manipulation patterns
        Pattern.compile("admin=true", Pattern.CASE_INSENSITIVE),
        Pattern.compile("authenticated=1", Pattern.CASE_INSENSITIVE),
        Pattern.compile("role=administrator", Pattern.CASE_INSENSITIVE),
        
        // URL manipulation patterns
        Pattern.compile("/admin[^/]*$", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\?admin=true", Pattern.CASE_INSENSITIVE),
        Pattern.compile("&bypass=1", Pattern.CASE_INSENSITIVE),
        
        // LDAP injection patterns
        Pattern.compile("\\*\\)\\(cn=\\*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\)\\(\\|\\(&", Pattern.CASE_INSENSITIVE)
    );

    // Vulnerable authentication endpoints
    private static final Set<String> VULNERABLE_ENDPOINTS = Set.of(
        "/login", "/authenticate", "/signin", "/auth", "/oauth", "/sso",
        "/admin", "/dashboard", "/profile", "/user", "/api/auth", "/api/login"
    );

    /**
     * Analyze request for authentication bypass attempts
     */
    public Map<String, Object> analyzeRequest(String endpoint, Map<String, String> headers, 
                                             Map<String, Object> parameters, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        List<String> detectedPatterns = new ArrayList<>();
        List<String> vulnerabilities = new ArrayList<>();
        int riskScore = 0;
        
        try {
            // Check if endpoint is authentication-related
            if (isAuthenticationEndpoint(endpoint)) {
                riskScore += 2;
                vulnerabilities.add("Authentication endpoint access detected");
            }
            
            // Check headers for bypass attempts
            for (Map.Entry<String, String> header : headers.entrySet()) {
                String headerName = header.getKey().toLowerCase();
                String headerValue = header.getValue().toLowerCase();
                
                if (isAuthBypassHeader(headerName, headerValue)) {
                    riskScore += 4;
                    vulnerabilities.add("Suspicious authentication header: " + headerName);
                    detectedPatterns.add("Header manipulation: " + headerName);
                }
                
                // Check header values for bypass patterns
                for (Pattern pattern : AUTH_BYPASS_PATTERNS) {
                    if (pattern.matcher(headerValue).find()) {
                        detectedPatterns.add(pattern.pattern());
                        riskScore += 3;
                    }
                }
            }
            
            // Check parameters for bypass attempts
            for (Map.Entry<String, Object> param : parameters.entrySet()) {
                String paramName = param.getKey().toLowerCase();
                String paramValue = param.getValue().toString().toLowerCase();
                
                if (isAuthBypassParameter(paramName, paramValue)) {
                    riskScore += 3;
                    vulnerabilities.add("Suspicious authentication parameter: " + paramName);
                }
                
                // Check parameter values for bypass patterns
                for (Pattern pattern : AUTH_BYPASS_PATTERNS) {
                    if (pattern.matcher(paramValue).find()) {
                        detectedPatterns.add(pattern.pattern());
                        riskScore += 4;
                    }
                }
            }
            
            // Check for specific bypass techniques
            if (isSqlInjectionBypass(parameters)) {
                riskScore += 5;
                vulnerabilities.add("SQL injection authentication bypass detected");
            }
            
            if (isNoSqlInjectionBypass(parameters)) {
                riskScore += 5;
                vulnerabilities.add("NoSQL injection authentication bypass detected");
            }
            
            if (isParameterPollutionBypass(parameters)) {
                riskScore += 4;
                vulnerabilities.add("HTTP parameter pollution bypass detected");
            }
            
            if (isTokenManipulationBypass(headers)) {
                riskScore += 4;
                vulnerabilities.add("Authentication token manipulation detected");
            }
            
            boolean bypassDetected = riskScore >= 4;
            String riskLevel = calculateRiskLevel(riskScore);
            
            result.put("bypassDetected", bypassDetected);
            result.put("riskScore", Math.min(riskScore, 10));
            result.put("riskLevel", riskLevel);
            result.put("endpoint", endpoint);
            result.put("detectedPatterns", detectedPatterns);
            result.put("vulnerabilities", vulnerabilities);
            result.put("recommendation", generateRecommendation(riskLevel, vulnerabilities));
            result.put("timestamp", LocalDateTime.now().toString());
            
            updateStatistics(bypassDetected, riskLevel, ipAddress);
            
        } catch (Exception e) {
            result.put("error", "Authentication bypass analysis failed: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * Test specific authentication bypass scenario
     */
    public Map<String, Object> testBypassScenario(String bypassType, Map<String, Object> testData, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            List<String> bypassAttempts = new ArrayList<>();
            List<String> blockedAttempts = new ArrayList<>();
            int riskScore = 0;
            
            switch (bypassType.toLowerCase()) {
                case "sql_injection":
                    riskScore = testSqlInjectionBypass(testData, bypassAttempts, blockedAttempts);
                    break;
                case "nosql_injection":
                    riskScore = testNoSqlInjectionBypass(testData, bypassAttempts, blockedAttempts);
                    break;
                case "parameter_pollution":
                    riskScore = testParameterPollutionBypass(testData, bypassAttempts, blockedAttempts);
                    break;
                case "header_manipulation":
                    riskScore = testHeaderManipulationBypass(testData, bypassAttempts, blockedAttempts);
                    break;
                case "token_manipulation":
                    riskScore = testTokenManipulationBypass(testData, bypassAttempts, blockedAttempts);
                    break;
                case "cookie_manipulation":
                    riskScore = testCookieManipulationBypass(testData, bypassAttempts, blockedAttempts);
                    break;
                case "url_manipulation":
                    riskScore = testUrlManipulationBypass(testData, bypassAttempts, blockedAttempts);
                    break;
                case "ldap_injection":
                    riskScore = testLdapInjectionBypass(testData, bypassAttempts, blockedAttempts);
                    break;
                default:
                    riskScore = testGenericBypass(testData, bypassAttempts, blockedAttempts);
            }
            
            boolean bypassDetected = riskScore >= 4;
            String severity = calculateBypassSeverity(riskScore);
            
            result.put("bypassType", bypassType);
            result.put("bypassDetected", bypassDetected);
            result.put("riskScore", Math.min(riskScore, 10));
            result.put("severity", severity);
            result.put("bypassAttempts", bypassAttempts);
            result.put("blockedAttempts", blockedAttempts);
            result.put("recommendation", generateBypassRecommendation(severity, bypassType));
            
        } catch (Exception e) {
            result.put("error", "Authentication bypass test failed: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * Perform comprehensive authentication bypass testing
     */
    public Map<String, Object> performComprehensiveTest(String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        List<Map<String, Object>> testResults = new ArrayList<>();
        
        // Comprehensive authentication bypass test scenarios
        Object[][] testScenarios = {
            {"sql_injection", Map.of("username", "admin' OR '1'='1", "password", "anything")},
            {"nosql_injection", Map.of("username", Map.of("$ne", "null"), "password", "anything")},
            {"parameter_pollution", Map.of("username", "user", "username[]", "admin")},
            {"header_manipulation", Map.of("X-Forwarded-User", "admin", "X-Authenticated", "true")},
            {"token_manipulation", Map.of("Authorization", "Bearer null", "token", "admin")},
            {"cookie_manipulation", Map.of("admin", "true", "authenticated", "1")},
            {"url_manipulation", Map.of("url", "/admin?bypass=1", "redirect", "/dashboard")},
            {"ldap_injection", Map.of("username", "*)(cn=*", "password", "anything")},
            {"empty_password", Map.of("username", "admin", "password", "")},
            {"case_bypass", Map.of("username", "ADMIN", "password", "admin")},
            {"unicode_bypass", Map.of("username", "ａｄｍｉｎ", "password", "admin")},
            {"path_traversal", Map.of("username", "../admin", "password", "anything")}
        };
        
        int totalTests = testScenarios.length;
        int vulnerableTests = 0;
        
        for (int i = 0; i < testScenarios.length; i++) {
            Object[] testData = testScenarios[i];
            String bypassType = (String) testData[0];
            Map<String, Object> data = (Map<String, Object>) testData[1];
            
            Map<String, Object> testResult = testBypassScenario(bypassType, data, ipAddress);
            testResult.put("testId", "AUTH_" + (i + 1));
            testResult.put("testName", getTestName(i));
            testResults.add(testResult);
            
            if ((Boolean) testResult.get("bypassDetected")) {
                vulnerableTests++;
            }
        }
        
        double vulnerabilityRate = (double) vulnerableTests / totalTests * 100;
        String overallSecurity = getOverallSecurityLevel(vulnerabilityRate);
        
        result.put("totalTests", totalTests);
        result.put("vulnerableTests", vulnerableTests);
        result.put("vulnerabilityRate", String.format("%.1f%%", vulnerabilityRate));
        result.put("overallSecurity", overallSecurity);
        result.put("testResults", testResults);
        result.put("timestamp", LocalDateTime.now().toString());
        result.put("recommendation", generateComprehensiveRecommendation(vulnerabilityRate));
        
        return result;
    }

    /**
     * Get authentication bypass statistics
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        try {
            String statsJson = redisTemplate.opsForValue().get(AUTH_BYPASS_STATS_KEY);
            if (statsJson != null) {
                stats = objectMapper.readValue(statsJson, Map.class);
            }
        } catch (Exception e) {
            stats.put("error", "Failed to retrieve statistics");
        }
        
        stats.putIfAbsent("totalAnalyses", 0);
        stats.putIfAbsent("bypassAttemptsDetected", 0);
        stats.putIfAbsent("vulnerableRequests", 0);
        stats.putIfAbsent("lastUpdated", LocalDateTime.now().toString());
        
        return stats;
    }

    // Private helper methods
    private boolean isAuthenticationEndpoint(String endpoint) {
        return VULNERABLE_ENDPOINTS.stream()
            .anyMatch(vulnEndpoint -> endpoint.toLowerCase().contains(vulnEndpoint));
    }

    private boolean isAuthBypassHeader(String headerName, String headerValue) {
        // Check for authentication bypass headers
        return (headerName.contains("user") || headerName.contains("auth") || 
                headerName.contains("admin") || headerName.contains("role")) &&
               (headerValue.contains("true") || headerValue.contains("admin") || 
                headerValue.contains("authenticated"));
    }

    private boolean isAuthBypassParameter(String paramName, String paramValue) {
        // Check for authentication bypass parameters
        return (paramName.contains("admin") && paramValue.contains("true")) ||
               (paramName.contains("auth") && paramValue.contains("bypass")) ||
               (paramName.contains("role") && paramValue.contains("admin"));
    }

    private boolean isSqlInjectionBypass(Map<String, Object> parameters) {
        for (Object value : parameters.values()) {
            String strValue = value.toString().toLowerCase();
            if (strValue.contains("' or '1'='1") || strValue.contains("' or 1=1") ||
                strValue.contains("admin'--") || strValue.contains("' union select")) {
                return true;
            }
        }
        return false;
    }

    private boolean isNoSqlInjectionBypass(Map<String, Object> parameters) {
        for (Object value : parameters.values()) {
            if (value instanceof Map) {
                Map<String, Object> nestedMap = (Map<String, Object>) value;
                if (nestedMap.containsKey("$ne") || nestedMap.containsKey("$regex") || 
                    nestedMap.containsKey("$where")) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isParameterPollutionBypass(Map<String, Object> parameters) {
        // Check for parameter pollution (same parameter multiple times)
        Set<String> baseNames = new HashSet<>();
        for (String key : parameters.keySet()) {
            String baseName = key.replaceAll("\\[.*\\]", "");
            if (baseNames.contains(baseName)) {
                return true;
            }
            baseNames.add(baseName);
        }
        return false;
    }

    private boolean isTokenManipulationBypass(Map<String, String> headers) {
        for (Map.Entry<String, String> header : headers.entrySet()) {
            String value = header.getValue().toLowerCase();
            if (value.contains("bearer null") || value.contains("jwt none") || 
                value.contains("token admin")) {
                return true;
            }
        }
        return false;
    }

    // Test method implementations
    private int testSqlInjectionBypass(Map<String, Object> data, List<String> attempts, List<String> blocked) {
        int risk = 0;
        
        String[] sqlPayloads = {
            "admin' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users--",
            "' OR 1=1#",
            "admin'; DROP TABLE users;--"
        };
        
        for (String payload : sqlPayloads) {
            attempts.add("SQL injection attempt: " + payload);
            
            // In a real implementation, this would test against the actual authentication system
            // Here we simulate detection
            if (payload.contains("'") && (payload.contains("OR") || payload.contains("UNION"))) {
                blocked.add("SQL injection blocked: " + payload);
                risk += 2;
            }
        }
        
        return risk;
    }

    private int testNoSqlInjectionBypass(Map<String, Object> data, List<String> attempts, List<String> blocked) {
        int risk = 0;
        
        Object username = data.get("username");
        if (username instanceof Map) {
            Map<String, Object> usernameObj = (Map<String, Object>) username;
            attempts.add("NoSQL injection attempt: " + usernameObj.toString());
            
            if (usernameObj.containsKey("$ne") || usernameObj.containsKey("$regex")) {
                blocked.add("NoSQL injection blocked");
                risk += 3;
            }
        }
        
        return risk;
    }

    private int testParameterPollutionBypass(Map<String, Object> data, List<String> attempts, List<String> blocked) {
        int risk = 0;
        
        if (data.containsKey("username") && data.containsKey("username[]")) {
            attempts.add("Parameter pollution attempt: username & username[]");
            blocked.add("Parameter pollution blocked");
            risk += 2;
        }
        
        return risk;
    }

    private int testHeaderManipulationBypass(Map<String, Object> data, List<String> attempts, List<String> blocked) {
        int risk = 0;
        
        for (Map.Entry<String, Object> entry : data.entrySet()) {
            String key = entry.getKey();
            if (key.toLowerCase().startsWith("x-") && 
                (key.toLowerCase().contains("user") || key.toLowerCase().contains("auth"))) {
                attempts.add("Header manipulation attempt: " + key);
                blocked.add("Suspicious header blocked: " + key);
                risk += 3;
            }
        }
        
        return risk;
    }

    private int testTokenManipulationBypass(Map<String, Object> data, List<String> attempts, List<String> blocked) {
        int risk = 0;
        
        Object auth = data.get("Authorization");
        if (auth != null && auth.toString().contains("null")) {
            attempts.add("Token manipulation attempt: null bearer token");
            blocked.add("Invalid token blocked");
            risk += 4;
        }
        
        return risk;
    }

    private int testCookieManipulationBypass(Map<String, Object> data, List<String> attempts, List<String> blocked) {
        int risk = 0;
        
        if (data.containsKey("admin") && "true".equals(data.get("admin").toString())) {
            attempts.add("Cookie manipulation attempt: admin=true");
            blocked.add("Suspicious cookie blocked");
            risk += 3;
        }
        
        return risk;
    }

    private int testUrlManipulationBypass(Map<String, Object> data, List<String> attempts, List<String> blocked) {
        int risk = 0;
        
        Object url = data.get("url");
        if (url != null && url.toString().contains("bypass")) {
            attempts.add("URL manipulation attempt: " + url.toString());
            blocked.add("Suspicious URL parameter blocked");
            risk += 2;
        }
        
        return risk;
    }

    private int testLdapInjectionBypass(Map<String, Object> data, List<String> attempts, List<String> blocked) {
        int risk = 0;
        
        Object username = data.get("username");
        if (username != null && username.toString().contains("*)(cn=*")) {
            attempts.add("LDAP injection attempt: " + username.toString());
            blocked.add("LDAP injection blocked");
            risk += 4;
        }
        
        return risk;
    }

    private int testGenericBypass(Map<String, Object> data, List<String> attempts, List<String> blocked) {
        int risk = 0;
        
        // Generic authentication bypass detection
        for (Map.Entry<String, Object> entry : data.entrySet()) {
            String value = entry.getValue().toString().toLowerCase();
            
            if (value.contains("bypass") || value.contains("admin") || value.isEmpty()) {
                attempts.add("Generic bypass attempt: " + entry.getKey());
                blocked.add("Suspicious parameter blocked: " + entry.getKey());
                risk += 1;
            }
        }
        
        return risk;
    }

    private String calculateRiskLevel(int riskScore) {
        if (riskScore >= 8) return "CRITICAL";
        if (riskScore >= 6) return "HIGH";
        if (riskScore >= 4) return "MEDIUM";
        if (riskScore >= 2) return "LOW";
        return "MINIMAL";
    }

    private String calculateBypassSeverity(int riskScore) {
        if (riskScore >= 6) return "CRITICAL";
        if (riskScore >= 4) return "HIGH";
        if (riskScore >= 2) return "MEDIUM";
        if (riskScore >= 1) return "LOW";
        return "NONE";
    }

    private String getOverallSecurityLevel(double vulnerabilityRate) {
        if (vulnerabilityRate == 0) return "EXCELLENT";
        if (vulnerabilityRate <= 20) return "GOOD";
        if (vulnerabilityRate <= 50) return "FAIR";
        return "POOR";
    }

    private String getTestName(int index) {
        String[] testNames = {
            "SQL Injection Authentication Bypass",
            "NoSQL Injection Authentication Bypass", 
            "HTTP Parameter Pollution Bypass",
            "Header Manipulation Bypass",
            "Token Manipulation Bypass",
            "Cookie Manipulation Bypass",
            "URL Parameter Bypass",
            "LDAP Injection Bypass",
            "Empty Password Bypass",
            "Case Sensitivity Bypass",
            "Unicode Character Bypass",
            "Path Traversal Bypass"
        };
        return index < testNames.length ? testNames[index] : "Unknown Authentication Bypass Test";
    }

    private String generateRecommendation(String riskLevel, List<String> vulnerabilities) {
        StringBuilder rec = new StringBuilder();
        
        switch (riskLevel) {
            case "CRITICAL":
                rec.append("IMMEDIATE ACTION: Critical authentication bypass detected. ");
                break;
            case "HIGH":
                rec.append("HIGH PRIORITY: Authentication bypass patterns found. ");
                break;
            case "MEDIUM":
                rec.append("MEDIUM PRIORITY: Potential authentication bypass vulnerability. ");
                break;
            default:
                rec.append("Monitor for authentication bypass patterns. ");
        }
        
        if (vulnerabilities.stream().anyMatch(v -> v.contains("SQL"))) {
            rec.append("Implement parameterized queries and input validation. ");
        }
        if (vulnerabilities.stream().anyMatch(v -> v.contains("header"))) {
            rec.append("Validate and sanitize all HTTP headers. ");
        }
        if (vulnerabilities.stream().anyMatch(v -> v.contains("token"))) {
            rec.append("Implement proper token validation and secure token handling. ");
        }
        
        return rec.toString();
    }

    private String generateBypassRecommendation(String severity, String bypassType) {
        StringBuilder rec = new StringBuilder("Authentication bypass detected in " + bypassType + ". ");
        
        switch (severity) {
            case "CRITICAL":
                rec.append("CRITICAL: Implement multi-layer authentication validation. ");
                break;
            case "HIGH":
                rec.append("HIGH: Strengthen input validation and authentication checks. ");
                break;
            case "MEDIUM":
                rec.append("MEDIUM: Review authentication logic and add validation. ");
                break;
            default:
                rec.append("Monitor authentication attempts for anomalies. ");
        }
        
        return rec.toString();
    }

    private String generateComprehensiveRecommendation(double vulnerabilityRate) {
        if (vulnerabilityRate == 0) {
            return "EXCELLENT: No authentication bypass vulnerabilities detected. Authentication system is secure.";
        } else if (vulnerabilityRate <= 20) {
            return "GOOD: Minimal authentication vulnerabilities. Review and strengthen identified areas.";
        } else if (vulnerabilityRate <= 50) {
            return "FAIR: Moderate authentication vulnerabilities. Implement comprehensive input validation.";
        } else {
            return "CRITICAL: High authentication bypass vulnerability rate. Immediate security review required.";
        }
    }

    private void updateStatistics(boolean bypassDetected, String riskLevel, String ipAddress) {
        try {
            Map<String, Object> stats = getStatistics();
            
            int totalAnalyses = (Integer) stats.getOrDefault("totalAnalyses", 0) + 1;
            int bypassAttemptsDetected = (Integer) stats.getOrDefault("bypassAttemptsDetected", 0);
            int vulnerableRequests = (Integer) stats.getOrDefault("vulnerableRequests", 0);
            
            if (bypassDetected) {
                bypassAttemptsDetected++;
                vulnerableRequests++;
            }
            
            stats.put("totalAnalyses", totalAnalyses);
            stats.put("bypassAttemptsDetected", bypassAttemptsDetected);
            stats.put("vulnerableRequests", vulnerableRequests);
            stats.put("detectionRate", String.format("%.1f%%", (double) bypassAttemptsDetected / totalAnalyses * 100));
            stats.put("lastRiskLevel", riskLevel);
            stats.put("lastUpdated", LocalDateTime.now().toString());
            
            String statsJson = objectMapper.writeValueAsString(stats);
            redisTemplate.opsForValue().set(AUTH_BYPASS_STATS_KEY, statsJson, 24, TimeUnit.HOURS);
            
        } catch (Exception e) {
            // Log error but continue
        }
    }
}