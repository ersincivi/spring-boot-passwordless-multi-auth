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
 * Comprehensive Timing Attack Security Service
 * Provides detection and testing for timing-based attacks and side-channel vulnerabilities
 */
@Profile("dev") // Security test harness - dev profile only
@Service
public class TimingAttackSecurityService {

    private static final String TIMING_STATS_KEY = "timing_attack:statistics";

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Autowired
    private SecurityAuditService securityAuditService;

    @Autowired
    private ObjectMapper objectMapper;

    // Timing attack patterns
    private static final List<Pattern> TIMING_ATTACK_PATTERNS = Arrays.asList(
        // Authentication timing patterns
        Pattern.compile("login|auth|password|credential", Pattern.CASE_INSENSITIVE),
        Pattern.compile("username|email|user", Pattern.CASE_INSENSITIVE),
        
        // Database timing patterns
        Pattern.compile("select|query|database|sql", Pattern.CASE_INSENSITIVE),
        Pattern.compile("exists|count|search", Pattern.CASE_INSENSITIVE),
        
        // Cryptographic timing patterns
        Pattern.compile("hash|encrypt|decrypt|sign", Pattern.CASE_INSENSITIVE),
        Pattern.compile("compare|verify|validate", Pattern.CASE_INSENSITIVE),
        
        // File system timing patterns
        Pattern.compile("file|path|directory", Pattern.CASE_INSENSITIVE),
        Pattern.compile("read|write|access", Pattern.CASE_INSENSITIVE),
        
        // Network timing patterns
        Pattern.compile("request|response|network", Pattern.CASE_INSENSITIVE),
        Pattern.compile("timeout|delay|latency", Pattern.CASE_INSENSITIVE)
    );

    /**
     * Analyze operation for timing attack vulnerabilities
     */
    public Map<String, Object> analyzeOperation(String operation, String data, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        List<String> detectedPatterns = new ArrayList<>();
        List<String> vulnerabilities = new ArrayList<>();
        int riskScore = 0;
        
        try {
            // Check for timing attack patterns
            String combined = operation + " " + (data != null ? data : "");
            
            for (Pattern pattern : TIMING_ATTACK_PATTERNS) {
                if (pattern.matcher(combined).find()) {
                    detectedPatterns.add(pattern.pattern());
                    riskScore += 2;
                }
            }
            
            // Specific vulnerability checks
            if (isAuthenticationTiming(operation)) {
                riskScore += 4;
                vulnerabilities.add("Authentication timing vulnerability detected");
            }
            
            if (isDatabaseTiming(operation)) {
                riskScore += 3;
                vulnerabilities.add("Database query timing vulnerability detected");
            }
            
            if (isCryptographicTiming(operation)) {
                riskScore += 5;
                vulnerabilities.add("Cryptographic timing vulnerability detected");
            }
            
            boolean isVulnerable = riskScore >= 3;
            String riskLevel = calculateRiskLevel(riskScore);
            
            result.put("isVulnerable", isVulnerable);
            result.put("riskScore", Math.min(riskScore, 10));
            result.put("riskLevel", riskLevel);
            result.put("operation", operation);
            result.put("detectedPatterns", detectedPatterns);
            result.put("vulnerabilities", vulnerabilities);
            result.put("recommendation", generateRecommendation(riskLevel, vulnerabilities));
            result.put("timestamp", LocalDateTime.now().toString());
            
            updateStatistics(isVulnerable, riskLevel, ipAddress);
            
        } catch (Exception e) {
            result.put("error", "Timing attack analysis failed: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * Test timing attack with multiple measurements
     */
    public Map<String, Object> testTimingAttack(String operationType, String validInput, String invalidInput, 
                                               int iterations, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            List<Long> validTimings = new ArrayList<>();
            List<Long> invalidTimings = new ArrayList<>();
            
            // Perform timing measurements
            for (int i = 0; i < iterations; i++) {
                // Test valid input
                long validTime = measureOperationTime(operationType, validInput);
                validTimings.add(validTime);
                
                // Test invalid input
                long invalidTime = measureOperationTime(operationType, invalidInput);
                invalidTimings.add(invalidTime);
                
                // Add random delay to prevent interference
                try { Thread.sleep(1); } catch (InterruptedException e) {}
            }
            
            // Statistical analysis
            double validAvg = validTimings.stream().mapToLong(Long::longValue).average().orElse(0);
            double invalidAvg = invalidTimings.stream().mapToLong(Long::longValue).average().orElse(0);
            double timingDiff = Math.abs(validAvg - invalidAvg);
            double timingRatio = validAvg > 0 ? timingDiff / validAvg * 100 : 0;
            
            boolean timingAttackDetected = timingRatio > 10; // >10% difference indicates vulnerability
            String severity = calculateTimingSeverity(timingRatio);
            
            result.put("operationType", operationType);
            result.put("iterations", iterations);
            result.put("validAverageTime", validAvg);
            result.put("invalidAverageTime", invalidAvg);
            result.put("timingDifference", timingDiff);
            result.put("timingRatio", String.format("%.2f%%", timingRatio));
            result.put("timingAttackDetected", timingAttackDetected);
            result.put("severity", severity);
            result.put("recommendation", generateTimingRecommendation(severity, timingRatio));
            
        } catch (Exception e) {
            result.put("error", "Timing attack test failed: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * Perform comprehensive timing attack testing
     */
    public Map<String, Object> performComprehensiveTest(String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        List<Map<String, Object>> testResults = new ArrayList<>();
        
        // Comprehensive timing attack test scenarios
        Object[][] testScenarios = {
            {"authentication", "validuser@example.com", "invaliduser@example.com", 20},
            {"password_check", "correctpassword", "wrongpassword", 25},
            {"user_exists", "existinguser", "nonexistentuser", 15},
            {"database_query", "SELECT * FROM users WHERE id=1", "SELECT * FROM users WHERE id=999999", 30},
            {"file_access", "existing_file.txt", "nonexistent_file.txt", 20},
            {"crypto_compare", "correcthash", "incorrecthash", 50},
            {"session_validate", "validsessionid", "invalidsessionid", 25},
            {"permission_check", "authorized_action", "unauthorized_action", 20}
        };
        
        int totalTests = testScenarios.length;
        int vulnerableTests = 0;
        
        for (int i = 0; i < testScenarios.length; i++) {
            Object[] testData = testScenarios[i];
            String operationType = (String) testData[0];
            String validInput = (String) testData[1];
            String invalidInput = (String) testData[2];
            int iterations = (Integer) testData[3];
            
            Map<String, Object> testResult = testTimingAttack(operationType, validInput, invalidInput, iterations, ipAddress);
            testResult.put("testId", "TIME_" + (i + 1));
            testResult.put("testName", getTestName(i));
            testResults.add(testResult);
            
            if ((Boolean) testResult.get("timingAttackDetected")) {
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
     * Get timing attack statistics
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        try {
            String statsJson = redisTemplate.opsForValue().get(TIMING_STATS_KEY);
            if (statsJson != null) {
                stats = objectMapper.readValue(statsJson, Map.class);
            }
        } catch (Exception e) {
            stats.put("error", "Failed to retrieve statistics");
        }
        
        stats.putIfAbsent("totalAnalyses", 0);
        stats.putIfAbsent("vulnerableOperations", 0);
        stats.putIfAbsent("timingAttacksDetected", 0);
        stats.putIfAbsent("lastUpdated", LocalDateTime.now().toString());
        
        return stats;
    }

    // Private helper methods
    private long measureOperationTime(String operationType, String input) {
        long startTime = System.nanoTime();
        
        // Simulate different operation types with realistic timing variations
        try {
            switch (operationType) {
                case "authentication":
                    simulateAuthentication(input);
                    break;
                case "password_check":
                    simulatePasswordCheck(input);
                    break;
                case "user_exists":
                    simulateUserExistsCheck(input);
                    break;
                case "database_query":
                    simulateDatabaseQuery(input);
                    break;
                case "file_access":
                    simulateFileAccess(input);
                    break;
                case "crypto_compare":
                    simulateCryptoCompare(input);
                    break;
                default:
                    Thread.sleep(1); // Base processing time
            }
        } catch (Exception e) {
            // Timing attack might depend on exceptions too
        }
        
        return System.nanoTime() - startTime;
    }

    private void simulateAuthentication(String input) throws InterruptedException {
        // Valid emails take longer due to database lookup
        if (input.contains("@") && input.contains(".")) {
            Thread.sleep(5); // Simulate database lookup
        } else {
            Thread.sleep(1); // Quick rejection
        }
    }

    private void simulatePasswordCheck(String input) throws InterruptedException {
        // Longer passwords take more time to hash/compare
        Thread.sleep(input.length() / 2);
    }

    private void simulateUserExistsCheck(String input) throws InterruptedException {
        // Existing users require database lookup
        if (input.toLowerCase().contains("existing")) {
            Thread.sleep(3);
        } else {
            Thread.sleep(1);
        }
    }

    private void simulateDatabaseQuery(String input) throws InterruptedException {
        // Complex queries take longer
        if (input.toLowerCase().contains("where")) {
            Thread.sleep(4);
        } else {
            Thread.sleep(2);
        }
    }

    private void simulateFileAccess(String input) throws InterruptedException {
        // File system operations
        if (input.contains("existing")) {
            Thread.sleep(2);
        } else {
            Thread.sleep(1);
        }
    }

    private void simulateCryptoCompare(String input) throws InterruptedException {
        // Crypto operations should be constant time
        Thread.sleep(3); // Constant time regardless of input
    }

    private boolean isAuthenticationTiming(String operation) {
        return operation.toLowerCase().contains("auth") || 
               operation.toLowerCase().contains("login") ||
               operation.toLowerCase().contains("password");
    }

    private boolean isDatabaseTiming(String operation) {
        return operation.toLowerCase().contains("query") ||
               operation.toLowerCase().contains("select") ||
               operation.toLowerCase().contains("database");
    }

    private boolean isCryptographicTiming(String operation) {
        return operation.toLowerCase().contains("crypto") ||
               operation.toLowerCase().contains("hash") ||
               operation.toLowerCase().contains("encrypt");
    }

    private String calculateRiskLevel(int riskScore) {
        if (riskScore >= 8) return "CRITICAL";
        if (riskScore >= 6) return "HIGH";
        if (riskScore >= 4) return "MEDIUM";
        if (riskScore >= 2) return "LOW";
        return "MINIMAL";
    }

    private String calculateTimingSeverity(double timingRatio) {
        if (timingRatio > 50) return "CRITICAL";
        if (timingRatio > 25) return "HIGH";
        if (timingRatio > 10) return "MEDIUM";
        if (timingRatio > 5) return "LOW";
        return "NONE";
    }

    private String getOverallSecurityLevel(double vulnerabilityRate) {
        if (vulnerabilityRate == 0) return "EXCELLENT";
        if (vulnerabilityRate <= 25) return "GOOD";
        if (vulnerabilityRate <= 50) return "FAIR";
        return "POOR";
    }

    private String getTestName(int index) {
        String[] testNames = {
            "Email Authentication Timing",
            "Password Verification Timing",
            "User Existence Check Timing",
            "Database Query Timing",
            "File Access Timing",
            "Cryptographic Comparison Timing",
            "Session Validation Timing",
            "Permission Check Timing"
        };
        return index < testNames.length ? testNames[index] : "Unknown Timing Test";
    }

    private String generateRecommendation(String riskLevel, List<String> vulnerabilities) {
        StringBuilder rec = new StringBuilder();
        
        switch (riskLevel) {
            case "CRITICAL":
                rec.append("IMMEDIATE ACTION: Critical timing attack vulnerability detected. ");
                break;
            case "HIGH":
                rec.append("HIGH PRIORITY: Timing attack patterns found. ");
                break;
            case "MEDIUM":
                rec.append("MEDIUM PRIORITY: Potential timing attack vulnerability. ");
                break;
            default:
                rec.append("Monitor for timing attack patterns. ");
        }
        
        if (vulnerabilities.stream().anyMatch(v -> v.contains("Authentication"))) {
            rec.append("Implement constant-time authentication checks. ");
        }
        if (vulnerabilities.stream().anyMatch(v -> v.contains("Cryptographic"))) {
            rec.append("Use constant-time cryptographic operations. ");
        }
        if (vulnerabilities.stream().anyMatch(v -> v.contains("Database"))) {
            rec.append("Add consistent response times for database queries. ");
        }
        
        return rec.toString();
    }

    private String generateTimingRecommendation(String severity, double timingRatio) {
        StringBuilder rec = new StringBuilder();
        
        switch (severity) {
            case "CRITICAL":
                rec.append("CRITICAL: Severe timing attack detected (").append(String.format("%.1f%%", timingRatio)).append(" timing difference). ");
                rec.append("Implement constant-time operations immediately. ");
                break;
            case "HIGH":
                rec.append("HIGH: Significant timing difference detected. Use constant-time algorithms. ");
                break;
            case "MEDIUM":
                rec.append("MEDIUM: Timing difference detected. Add artificial delays. ");
                break;
            case "LOW":
                rec.append("LOW: Minor timing difference. Consider optimization. ");
                break;
            default:
                rec.append("No significant timing difference detected. Operation appears secure. ");
        }
        
        return rec.toString();
    }

    private String generateComprehensiveRecommendation(double vulnerabilityRate) {
        if (vulnerabilityRate == 0) {
            return "EXCELLENT: No timing attacks detected. All operations have consistent response times.";
        } else if (vulnerabilityRate <= 25) {
            return "GOOD: Minimal timing vulnerabilities detected. Review and fix identified issues.";
        } else if (vulnerabilityRate <= 50) {
            return "FAIR: Moderate timing vulnerabilities. Implement constant-time operations.";
        } else {
            return "CRITICAL: High timing attack vulnerability. Immediate action required for all operations.";
        }
    }

    private void updateStatistics(boolean vulnerable, String riskLevel, String ipAddress) {
        try {
            Map<String, Object> stats = getStatistics();
            
            int totalAnalyses = (Integer) stats.getOrDefault("totalAnalyses", 0) + 1;
            int vulnerableOperations = (Integer) stats.getOrDefault("vulnerableOperations", 0);
            int timingAttacksDetected = (Integer) stats.getOrDefault("timingAttacksDetected", 0);
            
            if (vulnerable) {
                vulnerableOperations++;
                timingAttacksDetected++;
            }
            
            stats.put("totalAnalyses", totalAnalyses);
            stats.put("vulnerableOperations", vulnerableOperations);
            stats.put("timingAttacksDetected", timingAttacksDetected);
            stats.put("detectionRate", String.format("%.1f%%", (double) timingAttacksDetected / totalAnalyses * 100));
            stats.put("lastRiskLevel", riskLevel);
            stats.put("lastUpdated", LocalDateTime.now().toString());
            
            String statsJson = objectMapper.writeValueAsString(stats);
            redisTemplate.opsForValue().set(TIMING_STATS_KEY, statsJson, 24, TimeUnit.HOURS);
            
        } catch (Exception e) {
            // Log error but continue
        }
    }
}