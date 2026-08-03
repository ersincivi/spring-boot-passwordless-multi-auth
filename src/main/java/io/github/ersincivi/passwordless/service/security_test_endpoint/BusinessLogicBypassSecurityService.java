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
 * Comprehensive Business Logic Bypass Security Service
 * Provides detection and testing for business logic bypass vulnerabilities
 */
@Profile("dev") // Security test harness - dev profile only
@Service
public class BusinessLogicBypassSecurityService {

    private static final String BUSINESS_LOGIC_STATS_KEY = "business_logic:statistics";

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Autowired
    private SecurityAuditService securityAuditService;

    @Autowired
    private ObjectMapper objectMapper;

    // Business logic bypass patterns
    private static final List<Pattern> BUSINESS_LOGIC_PATTERNS = Arrays.asList(
        // Price manipulation patterns
        Pattern.compile("price|cost|amount|total|subtotal", Pattern.CASE_INSENSITIVE),
        Pattern.compile("discount|coupon|promo|offer", Pattern.CASE_INSENSITIVE),
        
        // Quantity manipulation patterns
        Pattern.compile("quantity|qty|count|number", Pattern.CASE_INSENSITIVE),
        Pattern.compile("limit|max|min|threshold", Pattern.CASE_INSENSITIVE),
        
        // Workflow bypass patterns
        Pattern.compile("step|stage|phase|status", Pattern.CASE_INSENSITIVE),
        Pattern.compile("workflow|process|flow|sequence", Pattern.CASE_INSENSITIVE),
        
        // Authentication bypass patterns
        Pattern.compile("login|auth|verify|check", Pattern.CASE_INSENSITIVE),
        Pattern.compile("bypass|skip|ignore|override", Pattern.CASE_INSENSITIVE),
        
        // Authorization bypass patterns
        Pattern.compile("admin|role|permission|access", Pattern.CASE_INSENSITIVE),
        Pattern.compile("privilege|right|grant|allow", Pattern.CASE_INSENSITIVE),
        
        // Financial logic patterns
        Pattern.compile("balance|credit|debit|transaction", Pattern.CASE_INSENSITIVE),
        Pattern.compile("transfer|payment|refund|withdraw", Pattern.CASE_INSENSITIVE),
        
        // Time-based logic patterns
        Pattern.compile("expire|timeout|duration|period", Pattern.CASE_INSENSITIVE),
        Pattern.compile("date|time|schedule|deadline", Pattern.CASE_INSENSITIVE)
    );

    // Business logic rules to validate
    private static final Map<String, BusinessRule> BUSINESS_RULES = Map.of(
        "price_validation", new BusinessRule("price", "gt", 0),
        "quantity_limit", new BusinessRule("quantity", "lte", 100),
        "discount_limit", new BusinessRule("discount", "lte", 50),
        "minimum_age", new BusinessRule("age", "gte", 18),
        "max_attempts", new BusinessRule("attempts", "lte", 5),
        "balance_positive", new BusinessRule("balance", "gte", 0),
        "future_date", new BusinessRule("expiry_date", "future", null),
        "valid_email", new BusinessRule("email", "format", "email")
    );

    /**
     * Analyze request for business logic bypass vulnerabilities
     */
    public Map<String, Object> analyzeBusinessLogic(String operation, Map<String, Object> data, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        List<String> detectedPatterns = new ArrayList<>();
        List<String> violations = new ArrayList<>();
        int riskScore = 0;
        
        try {
            // Check for business logic patterns
            String operationLower = operation.toLowerCase();
            for (Pattern pattern : BUSINESS_LOGIC_PATTERNS) {
                if (pattern.matcher(operationLower).find()) {
                    detectedPatterns.add(pattern.pattern());
                    riskScore += 1;
                }
            }
            
            // Validate business rules
            for (Map.Entry<String, BusinessRule> entry : BUSINESS_RULES.entrySet()) {
                String ruleName = entry.getKey();
                BusinessRule rule = entry.getValue();
                
                if (data.containsKey(rule.getField())) {
                    boolean isViolation = validateBusinessRule(rule, data);
                    if (isViolation) {
                        violations.add("Business rule violation: " + ruleName);
                        riskScore += 3;
                    }
                }
            }
            
            // Check for specific bypass attempts
            if (isPriceManipulation(data)) {
                riskScore += 5;
                violations.add("Price manipulation detected");
            }
            
            if (isQuantityManipulation(data)) {
                riskScore += 4;
                violations.add("Quantity manipulation detected");
            }
            
            if (isWorkflowBypass(operation, data)) {
                riskScore += 4;
                violations.add("Workflow bypass attempt detected");
            }
            
            boolean isVulnerable = riskScore >= 3;
            String riskLevel = calculateRiskLevel(riskScore);
            
            result.put("isVulnerable", isVulnerable);
            result.put("riskScore", Math.min(riskScore, 10));
            result.put("riskLevel", riskLevel);
            result.put("operation", operation);
            result.put("detectedPatterns", detectedPatterns);
            result.put("violations", violations);
            result.put("recommendation", generateRecommendation(riskLevel, violations));
            result.put("timestamp", LocalDateTime.now().toString());
            
            updateStatistics(isVulnerable, riskLevel, ipAddress);
            
        } catch (Exception e) {
            result.put("error", "Business logic analysis failed: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * Test specific business logic bypass scenario
     */
    public Map<String, Object> testBusinessLogicBypass(String scenarioType, Map<String, Object> testData, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            List<String> bypassAttempts = new ArrayList<>();
            List<String> blockedAttempts = new ArrayList<>();
            int riskScore = 0;
            
            switch (scenarioType.toLowerCase()) {
                case "price_manipulation":
                    riskScore = testPriceManipulation(testData, bypassAttempts, blockedAttempts);
                    break;
                case "quantity_bypass":
                    riskScore = testQuantityBypass(testData, bypassAttempts, blockedAttempts);
                    break;
                case "workflow_skip":
                    riskScore = testWorkflowSkip(testData, bypassAttempts, blockedAttempts);
                    break;
                case "authentication_bypass":
                    riskScore = testAuthenticationBypass(testData, bypassAttempts, blockedAttempts);
                    break;
                case "authorization_escalation":
                    riskScore = testAuthorizationEscalation(testData, bypassAttempts, blockedAttempts);
                    break;
                case "financial_logic":
                    riskScore = testFinancialLogic(testData, bypassAttempts, blockedAttempts);
                    break;
                default:
                    riskScore = testGenericLogic(testData, bypassAttempts, blockedAttempts);
            }
            
            boolean bypassDetected = riskScore >= 4;
            String severity = calculateBusinessLogicSeverity(riskScore);
            
            result.put("scenarioType", scenarioType);
            result.put("bypassDetected", bypassDetected);
            result.put("riskScore", Math.min(riskScore, 10));
            result.put("severity", severity);
            result.put("bypassAttempts", bypassAttempts);
            result.put("blockedAttempts", blockedAttempts);
            result.put("recommendation", generateBypassRecommendation(severity, scenarioType));
            
        } catch (Exception e) {
            result.put("error", "Business logic bypass test failed: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * Perform comprehensive business logic testing
     */
    public Map<String, Object> performComprehensiveTest(String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        List<Map<String, Object>> testResults = new ArrayList<>();
        
        // Comprehensive business logic test scenarios
        Object[][] testScenarios = {
            {"price_manipulation", Map.of("price", -10.0, "originalPrice", 100.0)},
            {"quantity_bypass", Map.of("quantity", 999, "maxQuantity", 10)},
            {"workflow_skip", Map.of("currentStep", 3, "requiredStep", 1, "completed", false)},
            {"authentication_bypass", Map.of("authenticated", false, "adminAccess", true)},
            {"authorization_escalation", Map.of("userRole", "user", "requestedRole", "admin")},
            {"financial_logic", Map.of("balance", 50.0, "withdrawAmount", 100.0)},
            {"age_verification", Map.of("age", 16, "requiredAge", 18)},
            {"discount_abuse", Map.of("discount", 90, "maxDiscount", 20)},
            {"expiry_bypass", Map.of("expiryDate", "2020-01-01", "currentDate", "2024-01-01")},
            {"limit_exceeded", Map.of("attempts", 10, "maxAttempts", 3)}
        };
        
        int totalTests = testScenarios.length;
        int vulnerableTests = 0;
        
        for (int i = 0; i < testScenarios.length; i++) {
            Object[] testData = testScenarios[i];
            String scenarioType = (String) testData[0];
            Map<String, Object> data = (Map<String, Object>) testData[1];
            
            Map<String, Object> testResult = testBusinessLogicBypass(scenarioType, data, ipAddress);
            testResult.put("testId", "BL_" + (i + 1));
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
     * Get business logic statistics
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        try {
            String statsJson = redisTemplate.opsForValue().get(BUSINESS_LOGIC_STATS_KEY);
            if (statsJson != null) {
                stats = objectMapper.readValue(statsJson, Map.class);
            }
        } catch (Exception e) {
            stats.put("error", "Failed to retrieve statistics");
        }
        
        stats.putIfAbsent("totalAnalyses", 0);
        stats.putIfAbsent("vulnerableOperations", 0);
        stats.putIfAbsent("bypassAttemptsDetected", 0);
        stats.putIfAbsent("lastUpdated", LocalDateTime.now().toString());
        
        return stats;
    }

    // Private helper methods
    private boolean validateBusinessRule(BusinessRule rule, Map<String, Object> data) {
        Object value = data.get(rule.getField());
        if (value == null) return false;
        
        switch (rule.getOperator()) {
            case "gt":
                return ((Number) value).doubleValue() <= ((Number) rule.getValue()).doubleValue();
            case "gte":
                return ((Number) value).doubleValue() < ((Number) rule.getValue()).doubleValue();
            case "lt":
                return ((Number) value).doubleValue() >= ((Number) rule.getValue()).doubleValue();
            case "lte":
                return ((Number) value).doubleValue() > ((Number) rule.getValue()).doubleValue();
            case "future":
                return LocalDateTime.parse(value.toString()).isBefore(LocalDateTime.now());
            case "format":
                if ("email".equals(rule.getValue())) {
                    return !value.toString().matches("^[A-Za-z0-9+_.-]+@(.+)$");
                }
                break;
        }
        return false;
    }

    private boolean isPriceManipulation(Map<String, Object> data) {
        Object price = data.get("price");
        if (price != null) {
            double priceValue = ((Number) price).doubleValue();
            return priceValue < 0 || priceValue > 1000000; // Negative or unreasonably high
        }
        return false;
    }

    private boolean isQuantityManipulation(Map<String, Object> data) {
        Object quantity = data.get("quantity");
        if (quantity != null) {
            int quantityValue = ((Number) quantity).intValue();
            return quantityValue < 0 || quantityValue > 1000; // Negative or unreasonably high
        }
        return false;
    }

    private boolean isWorkflowBypass(String operation, Map<String, Object> data) {
        // Check if trying to access later steps without completing earlier ones
        Object currentStep = data.get("currentStep");
        Object completed = data.get("completed");
        
        if (currentStep != null && completed != null) {
            return operation.toLowerCase().contains("complete") && !(Boolean) completed;
        }
        return false;
    }

    private int testPriceManipulation(Map<String, Object> data, List<String> attempts, List<String> blocked) {
        int risk = 0;
        Object price = data.get("price");
        
        if (price != null) {
            double priceValue = ((Number) price).doubleValue();
            
            if (priceValue < 0) {
                attempts.add("Negative price bypass attempt");
                blocked.add("Negative price blocked");
                risk += 5;
            }
            
            if (priceValue == 0) {
                attempts.add("Zero price bypass attempt");
                blocked.add("Zero price blocked");
                risk += 4;
            }
            
            Object originalPrice = data.get("originalPrice");
            if (originalPrice != null) {
                double originalPriceValue = ((Number) originalPrice).doubleValue();
                if (priceValue < originalPriceValue * 0.1) { // More than 90% discount
                    attempts.add("Excessive discount bypass attempt");
                    blocked.add("Excessive discount blocked");
                    risk += 3;
                }
            }
        }
        
        return risk;
    }

    private int testQuantityBypass(Map<String, Object> data, List<String> attempts, List<String> blocked) {
        int risk = 0;
        Object quantity = data.get("quantity");
        Object maxQuantity = data.get("maxQuantity");
        
        if (quantity != null && maxQuantity != null) {
            int quantityValue = ((Number) quantity).intValue();
            int maxQuantityValue = ((Number) maxQuantity).intValue();
            
            if (quantityValue > maxQuantityValue) {
                attempts.add("Quantity limit bypass attempt");
                blocked.add("Quantity limit enforced");
                risk += 4;
            }
            
            if (quantityValue < 0) {
                attempts.add("Negative quantity bypass attempt");
                blocked.add("Negative quantity blocked");
                risk += 5;
            }
        }
        
        return risk;
    }

    private int testWorkflowSkip(Map<String, Object> data, List<String> attempts, List<String> blocked) {
        int risk = 0;
        Object currentStep = data.get("currentStep");
        Object requiredStep = data.get("requiredStep");
        Object completed = data.get("completed");
        
        if (currentStep != null && requiredStep != null) {
            int current = ((Number) currentStep).intValue();
            int required = ((Number) requiredStep).intValue();
            
            if (current > required) {
                attempts.add("Workflow step skip attempt");
                blocked.add("Workflow step validation enforced");
                risk += 4;
            }
        }
        
        if (completed != null && !(Boolean) completed) {
            attempts.add("Incomplete workflow bypass attempt");
            blocked.add("Workflow completion required");
            risk += 3;
        }
        
        return risk;
    }

    private int testAuthenticationBypass(Map<String, Object> data, List<String> attempts, List<String> blocked) {
        int risk = 0;
        Object authenticated = data.get("authenticated");
        Object adminAccess = data.get("adminAccess");
        
        if (authenticated != null && adminAccess != null) {
            boolean isAuth = (Boolean) authenticated;
            boolean isAdmin = (Boolean) adminAccess;
            
            if (!isAuth && isAdmin) {
                attempts.add("Authentication bypass attempt");
                blocked.add("Authentication required");
                risk += 6;
            }
        }
        
        return risk;
    }

    private int testAuthorizationEscalation(Map<String, Object> data, List<String> attempts, List<String> blocked) {
        int risk = 0;
        Object userRole = data.get("userRole");
        Object requestedRole = data.get("requestedRole");
        
        if (userRole != null && requestedRole != null) {
            String currentRole = userRole.toString().toLowerCase();
            String requested = requestedRole.toString().toLowerCase();
            
            if ("user".equals(currentRole) && "admin".equals(requested)) {
                attempts.add("Privilege escalation attempt");
                blocked.add("Privilege escalation blocked");
                risk += 6;
            }
        }
        
        return risk;
    }

    private int testFinancialLogic(Map<String, Object> data, List<String> attempts, List<String> blocked) {
        int risk = 0;
        Object balance = data.get("balance");
        Object withdrawAmount = data.get("withdrawAmount");
        
        if (balance != null && withdrawAmount != null) {
            double balanceValue = ((Number) balance).doubleValue();
            double withdrawValue = ((Number) withdrawAmount).doubleValue();
            
            if (withdrawValue > balanceValue) {
                attempts.add("Insufficient funds bypass attempt");
                blocked.add("Insufficient funds check enforced");
                risk += 5;
            }
        }
        
        return risk;
    }

    private int testGenericLogic(Map<String, Object> data, List<String> attempts, List<String> blocked) {
        int risk = 0;
        
        // Generic business logic validation
        for (Map.Entry<String, Object> entry : data.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            
            if (value instanceof Number) {
                double numValue = ((Number) value).doubleValue();
                if (numValue < 0) {
                    attempts.add("Negative value bypass: " + key);
                    blocked.add("Negative value blocked: " + key);
                    risk += 2;
                }
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

    private String calculateBusinessLogicSeverity(int riskScore) {
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
            "Price Manipulation Test",
            "Quantity Limit Bypass Test",
            "Workflow Skip Test",
            "Authentication Bypass Test",
            "Authorization Escalation Test",
            "Financial Logic Test",
            "Age Verification Test",
            "Discount Abuse Test",
            "Expiry Date Bypass Test",
            "Attempt Limit Test"
        };
        return index < testNames.length ? testNames[index] : "Unknown Business Logic Test";
    }

    private String generateRecommendation(String riskLevel, List<String> violations) {
        StringBuilder rec = new StringBuilder();
        
        switch (riskLevel) {
            case "CRITICAL":
                rec.append("IMMEDIATE ACTION: Critical business logic vulnerabilities detected. ");
                break;
            case "HIGH":
                rec.append("HIGH PRIORITY: Business logic bypass patterns found. ");
                break;
            case "MEDIUM":
                rec.append("MEDIUM PRIORITY: Potential business logic vulnerabilities. ");
                break;
            default:
                rec.append("Monitor for business logic bypass patterns. ");
        }
        
        if (violations.stream().anyMatch(v -> v.contains("Price"))) {
            rec.append("Implement server-side price validation. ");
        }
        if (violations.stream().anyMatch(v -> v.contains("Quantity"))) {
            rec.append("Enforce quantity limits on server side. ");
        }
        if (violations.stream().anyMatch(v -> v.contains("Workflow"))) {
            rec.append("Validate workflow state transitions. ");
        }
        
        return rec.toString();
    }

    private String generateBypassRecommendation(String severity, String scenarioType) {
        StringBuilder rec = new StringBuilder("Business logic bypass detected in " + scenarioType + ". ");
        
        switch (severity) {
            case "CRITICAL":
                rec.append("CRITICAL: Implement immediate server-side validation. ");
                break;
            case "HIGH":
                rec.append("HIGH: Strengthen business rule enforcement. ");
                break;
            case "MEDIUM":
                rec.append("MEDIUM: Review and enhance business logic validation. ");
                break;
            default:
                rec.append("Monitor business rule compliance. ");
        }
        
        return rec.toString();
    }

    private String generateComprehensiveRecommendation(double vulnerabilityRate) {
        if (vulnerabilityRate == 0) {
            return "EXCELLENT: No business logic bypasses detected. All business rules properly enforced.";
        } else if (vulnerabilityRate <= 20) {
            return "GOOD: Minimal business logic vulnerabilities. Review and fix identified issues.";
        } else if (vulnerabilityRate <= 50) {
            return "FAIR: Moderate business logic vulnerabilities. Strengthen server-side validation.";
        } else {
            return "CRITICAL: High business logic vulnerability rate. Immediate comprehensive review required.";
        }
    }

    private void updateStatistics(boolean vulnerable, String riskLevel, String ipAddress) {
        try {
            Map<String, Object> stats = getStatistics();
            
            int totalAnalyses = (Integer) stats.getOrDefault("totalAnalyses", 0) + 1;
            int vulnerableOperations = (Integer) stats.getOrDefault("vulnerableOperations", 0);
            int bypassAttemptsDetected = (Integer) stats.getOrDefault("bypassAttemptsDetected", 0);
            
            if (vulnerable) {
                vulnerableOperations++;
                bypassAttemptsDetected++;
            }
            
            stats.put("totalAnalyses", totalAnalyses);
            stats.put("vulnerableOperations", vulnerableOperations);
            stats.put("bypassAttemptsDetected", bypassAttemptsDetected);
            stats.put("detectionRate", String.format("%.1f%%", (double) bypassAttemptsDetected / totalAnalyses * 100));
            stats.put("lastRiskLevel", riskLevel);
            stats.put("lastUpdated", LocalDateTime.now().toString());
            
            String statsJson = objectMapper.writeValueAsString(stats);
            redisTemplate.opsForValue().set(BUSINESS_LOGIC_STATS_KEY, statsJson, 24, TimeUnit.HOURS);
            
        } catch (Exception e) {
            // Log error but continue
        }
    }

    // Business Rule class for validation
    private static class BusinessRule {
        private final String field;
        private final String operator;
        private final Object value;

        public BusinessRule(String field, String operator, Object value) {
            this.field = field;
            this.operator = operator;
            this.value = value;
        }

        public String getField() { return field; }
        public String getOperator() { return operator; }
        public Object getValue() { return value; }
    }
}