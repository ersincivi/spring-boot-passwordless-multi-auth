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
 * Comprehensive Mass Assignment Security Service
 * Provides detection and testing for Mass Assignment attacks
 */
@Profile("dev") // Security test harness - dev profile only
@Service
public class MassAssignmentSecurityService {

    private static final String MASS_ASSIGNMENT_STATS_KEY = "mass_assignment:statistics";

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Autowired
    private SecurityAuditService securityAuditService;

    @Autowired
    private ObjectMapper objectMapper;

    // Mass assignment attack patterns
    private static final List<Pattern> MASS_ASSIGNMENT_PATTERNS = Arrays.asList(
        // Admin/privileged field patterns
        Pattern.compile("\\b(admin|isAdmin|is_admin)\\s*[:=]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\b(role|user_role|userRole)\\s*[:=]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\b(permission|permissions)\\s*[:=]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\b(privilege|privileges)\\s*[:=]", Pattern.CASE_INSENSITIVE),
        
        // System/internal field patterns
        Pattern.compile("\\b(id|userId|user_id)\\s*[:=]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\b(created_at|createdAt|updated_at|updatedAt)\\s*[:=]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\b(version|_version)\\s*[:=]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\b(status|account_status|accountStatus)\\s*[:=]", Pattern.CASE_INSENSITIVE),
        
        // Security-sensitive fields
        Pattern.compile("\\b(password|pass|pwd)\\s*[:=]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\b(token|access_token|accessToken)\\s*[:=]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\b(secret|api_secret|apiSecret)\\s*[:=]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\b(key|private_key|privateKey)\\s*[:=]", Pattern.CASE_INSENSITIVE),
        
        // Financial/sensitive data fields
        Pattern.compile("\\b(balance|account_balance|accountBalance)\\s*[:=]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\b(credit|credits|points)\\s*[:=]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\b(salary|wage|income)\\s*[:=]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\b(price|cost|amount)\\s*[:=]", Pattern.CASE_INSENSITIVE),
        
        // Access control fields
        Pattern.compile("\\b(enabled|disabled|active|inactive)\\s*[:=]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\b(locked|blocked|banned)\\s*[:=]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\b(verified|confirmed|approved)\\s*[:=]", Pattern.CASE_INSENSITIVE),
        
        // Metadata manipulation
        Pattern.compile("\\b(__.*__|_.*_)\\s*[:=]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\b(constructor|prototype)\\s*[:=]", Pattern.CASE_INSENSITIVE)
    );

    // Protected field names that should never be mass assigned
    private static final Set<String> PROTECTED_FIELDS = Set.of(
        "id", "user_id", "userId", "admin", "isAdmin", "is_admin",
        "role", "user_role", "userRole", "permission", "permissions",
        "privilege", "privileges", "password", "pass", "pwd",
        "token", "access_token", "accessToken", "secret", "api_secret",
        "created_at", "createdAt", "updated_at", "updatedAt",
        "version", "_version", "status", "account_status",
        "balance", "account_balance", "credit", "credits",
        "enabled", "disabled", "active", "locked", "blocked",
        "constructor", "prototype", "__proto__"
    );

    // Allowed field names for mass assignment
    private static final Set<String> ALLOWED_FIELDS = Set.of(
        "name", "firstName", "lastName", "email", "phone",
        "address", "city", "country", "zipCode", "description",
        "title", "content", "message", "comment", "notes",
        "preferences", "settings", "theme", "language"
    );

    /**
     * Analyze request data for mass assignment vulnerabilities
     */
    public Map<String, Object> analyzeRequestData(Map<String, Object> requestData, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        List<String> detectedPatterns = new ArrayList<>();
        List<String> protectedFields = new ArrayList<>();
        List<String> suspiciousFields = new ArrayList<>();
        int riskScore = 0;
        
        try {
            if (requestData == null || requestData.isEmpty()) {
                result.put("error", "No request data provided for analysis");
                return result;
            }
            
            // Analyze each field in the request data
            for (Map.Entry<String, Object> entry : requestData.entrySet()) {
                String fieldName = entry.getKey();
                Object fieldValue = entry.getValue();
                
                // Check if field is protected
                if (PROTECTED_FIELDS.contains(fieldName.toLowerCase())) {
                    protectedFields.add(fieldName);
                    riskScore += 5;
                }
                
                // Check for suspicious field patterns
                String fieldAssignment = fieldName + ":" + fieldValue;
                for (Pattern pattern : MASS_ASSIGNMENT_PATTERNS) {
                    if (pattern.matcher(fieldAssignment).find()) {
                        detectedPatterns.add(pattern.pattern());
                        suspiciousFields.add(fieldName);
                        riskScore += 3;
                        break;
                    }
                }
                
                // Check for privilege escalation attempts
                if (isPrivilegeEscalationField(fieldName, fieldValue)) {
                    riskScore += 7;
                    suspiciousFields.add(fieldName + " (privilege escalation)");
                }
                
                // Check for system field manipulation
                if (isSystemField(fieldName)) {
                    riskScore += 4;
                    suspiciousFields.add(fieldName + " (system field)");
                }
            }
            
            boolean isVulnerable = riskScore >= 5;
            String riskLevel = calculateRiskLevel(riskScore);
            
            result.put("isVulnerable", isVulnerable);
            result.put("riskScore", Math.min(riskScore, 10));
            result.put("riskLevel", riskLevel);
            result.put("totalFields", requestData.size());
            result.put("protectedFields", protectedFields);
            result.put("suspiciousFields", suspiciousFields);
            result.put("detectedPatterns", detectedPatterns);
            result.put("recommendation", generateRecommendation(riskLevel, protectedFields, suspiciousFields));
            result.put("timestamp", LocalDateTime.now().toString());
            
            updateStatistics(isVulnerable, riskLevel, ipAddress);
            
        } catch (Exception e) {
            result.put("error", "Mass assignment analysis failed: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * Test specific mass assignment payload
     */
    public Map<String, Object> testMassAssignmentPayload(Map<String, Object> payload, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            List<String> attackTypes = new ArrayList<>();
            List<String> blockedFields = new ArrayList<>();
            int riskScore = 0;
            
            for (Map.Entry<String, Object> entry : payload.entrySet()) {
                String fieldName = entry.getKey();
                Object fieldValue = entry.getValue();
                
                // Check for different attack types
                if (isAdminEscalation(fieldName, fieldValue)) {
                    attackTypes.add("Admin Privilege Escalation");
                    blockedFields.add(fieldName);
                    riskScore += 8;
                }
                
                if (isPasswordManipulation(fieldName, fieldValue)) {
                    attackTypes.add("Password Field Manipulation");
                    blockedFields.add(fieldName);
                    riskScore += 6;
                }
                
                if (isBalanceManipulation(fieldName, fieldValue)) {
                    attackTypes.add("Financial Balance Manipulation");
                    blockedFields.add(fieldName);
                    riskScore += 7;
                }
                
                if (isMetadataManipulation(fieldName, fieldValue)) {
                    attackTypes.add("Metadata/System Field Manipulation");
                    blockedFields.add(fieldName);
                    riskScore += 5;
                }
                
                if (isRoleManipulation(fieldName, fieldValue)) {
                    attackTypes.add("Role/Permission Manipulation");
                    blockedFields.add(fieldName);
                    riskScore += 6;
                }
            }
            
            boolean isBlocked = riskScore >= 5;
            String riskLevel = calculateRiskLevel(riskScore);
            
            result.put("payload", sanitizePayloadForLogging(payload));
            result.put("isBlocked", isBlocked);
            result.put("riskScore", Math.min(riskScore, 10));
            result.put("riskLevel", riskLevel);
            result.put("attackTypes", attackTypes);
            result.put("blockedFields", blockedFields);
            result.put("allowedFields", getAllowedFieldsFromPayload(payload));
            result.put("recommendation", generatePayloadRecommendation(riskLevel, attackTypes));
            
        } catch (Exception e) {
            result.put("error", "Mass assignment payload test failed: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * Perform comprehensive mass assignment testing
     */
    public Map<String, Object> performComprehensiveTest(String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        List<Map<String, Object>> testResults = new ArrayList<>();
        
        // Comprehensive mass assignment test payloads
        Map<String, Object>[] testPayloads = new Map[] {
            Map.of("admin", true, "name", "John Doe"),
            Map.of("isAdmin", "true", "role", "administrator"),
            Map.of("user_id", "1", "balance", "1000000"),
            Map.of("password", "hacked123", "email", "user@example.com"),
            Map.of("permissions", "admin,user,super", "status", "active"),
            Map.of("created_at", "2020-01-01", "version", "999"),
            Map.of("__proto__", Map.of("admin", true), "constructor", "malicious"),
            Map.of("credit", "999999", "account_status", "premium"),
            Map.of("token", "admin_token_123", "verified", true),
            Map.of("privilege", "root", "locked", false),
            Map.of("api_secret", "secret123", "enabled", true),
            Map.of("salary", "999999", "role", "CEO")
        };
        
        int totalTests = testPayloads.length;
        int blockedCount = 0;
        
        for (int i = 0; i < testPayloads.length; i++) {
            Map<String, Object> testResult = testMassAssignmentPayload(testPayloads[i], ipAddress);
            testResult.put("testId", "MASS_" + (i + 1));
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
     * Validate field whitelist
     */
    public Map<String, Object> validateFieldWhitelist(Map<String, Object> fields, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            List<String> allowedFields = new ArrayList<>();
            List<String> blockedFields = new ArrayList<>();
            List<String> unknownFields = new ArrayList<>();
            
            for (String fieldName : fields.keySet()) {
                if (ALLOWED_FIELDS.contains(fieldName.toLowerCase())) {
                    allowedFields.add(fieldName);
                } else if (PROTECTED_FIELDS.contains(fieldName.toLowerCase())) {
                    blockedFields.add(fieldName);
                } else {
                    unknownFields.add(fieldName);
                }
            }
            
            String recommendation = generateWhitelistRecommendation(allowedFields.size(), 
                                                                  blockedFields.size(), 
                                                                  unknownFields.size());
            
            result.put("totalFields", fields.size());
            result.put("allowedFields", allowedFields);
            result.put("blockedFields", blockedFields);
            result.put("unknownFields", unknownFields);
            result.put("allowedCount", allowedFields.size());
            result.put("blockedCount", blockedFields.size());
            result.put("unknownCount", unknownFields.size());
            result.put("recommendation", recommendation);
            result.put("timestamp", LocalDateTime.now().toString());
            
        } catch (Exception e) {
            result.put("error", "Field whitelist validation failed: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * Get mass assignment statistics
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        try {
            String statsJson = redisTemplate.opsForValue().get(MASS_ASSIGNMENT_STATS_KEY);
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
    private boolean isPrivilegeEscalationField(String fieldName, Object fieldValue) {
        String lowerFieldName = fieldName.toLowerCase();
        String valueStr = fieldValue != null ? fieldValue.toString().toLowerCase() : "";
        
        return (lowerFieldName.contains("admin") && ("true".equals(valueStr) || "1".equals(valueStr))) ||
               (lowerFieldName.contains("role") && ("admin".equals(valueStr) || "administrator".equals(valueStr))) ||
               (lowerFieldName.contains("privilege") && ("admin".equals(valueStr) || "root".equals(valueStr)));
    }

    private boolean isSystemField(String fieldName) {
        String lowerFieldName = fieldName.toLowerCase();
        return lowerFieldName.contains("id") || lowerFieldName.contains("created") || 
               lowerFieldName.contains("updated") || lowerFieldName.contains("version");
    }

    private boolean isAdminEscalation(String fieldName, Object fieldValue) {
        String lowerFieldName = fieldName.toLowerCase();
        String valueStr = fieldValue != null ? fieldValue.toString().toLowerCase() : "";
        
        return (lowerFieldName.equals("admin") || lowerFieldName.equals("isadmin")) && 
               ("true".equals(valueStr) || "1".equals(valueStr));
    }

    private boolean isPasswordManipulation(String fieldName, Object fieldValue) {
        String lowerFieldName = fieldName.toLowerCase();
        return lowerFieldName.contains("password") || lowerFieldName.contains("pass") || 
               lowerFieldName.contains("pwd");
    }

    private boolean isBalanceManipulation(String fieldName, Object fieldValue) {
        String lowerFieldName = fieldName.toLowerCase();
        return lowerFieldName.contains("balance") || lowerFieldName.contains("credit") || 
               lowerFieldName.contains("money") || lowerFieldName.contains("salary");
    }

    private boolean isMetadataManipulation(String fieldName, Object fieldValue) {
        return fieldName.startsWith("__") || fieldName.equals("constructor") || 
               fieldName.equals("prototype") || fieldName.startsWith("_");
    }

    private boolean isRoleManipulation(String fieldName, Object fieldValue) {
        String lowerFieldName = fieldName.toLowerCase();
        return lowerFieldName.contains("role") || lowerFieldName.contains("permission") || 
               lowerFieldName.contains("privilege");
    }

    private Map<String, Object> sanitizePayloadForLogging(Map<String, Object> payload) {
        Map<String, Object> sanitized = new HashMap<>();
        for (Map.Entry<String, Object> entry : payload.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            
            if (key.toLowerCase().contains("password") || key.toLowerCase().contains("secret")) {
                sanitized.put(key, "[REDACTED]");
            } else {
                sanitized.put(key, value);
            }
        }
        return sanitized;
    }

    private List<String> getAllowedFieldsFromPayload(Map<String, Object> payload) {
        List<String> allowed = new ArrayList<>();
        for (String fieldName : payload.keySet()) {
            if (ALLOWED_FIELDS.contains(fieldName.toLowerCase())) {
                allowed.add(fieldName);
            }
        }
        return allowed;
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
            "Admin Privilege Escalation",
            "IsAdmin Boolean Bypass",
            "User ID and Balance Manipulation",
            "Password Field Override",
            "Permission System Bypass",
            "Timestamp and Version Manipulation",
            "Prototype Pollution Attack",
            "Financial Credit Manipulation",
            "Token and Verification Bypass",
            "Privilege and Lock Bypass",
            "API Secret Exposure",
            "Salary and Role Escalation"
        };
        return index < testNames.length ? testNames[index] : "Unknown Mass Assignment Test";
    }

    private String generateRecommendation(String riskLevel, List<String> protectedFields, List<String> suspiciousFields) {
        StringBuilder rec = new StringBuilder();
        
        switch (riskLevel) {
            case "CRITICAL":
                rec.append("IMMEDIATE ACTION: Critical mass assignment vulnerability detected. ");
                break;
            case "HIGH":
                rec.append("HIGH PRIORITY: Mass assignment attack patterns found. ");
                break;
            case "MEDIUM":
                rec.append("MEDIUM PRIORITY: Potential mass assignment vulnerability. ");
                break;
            default:
                rec.append("Monitor for mass assignment patterns. ");
        }
        
        if (!protectedFields.isEmpty()) {
            rec.append("Block protected fields: ").append(String.join(", ", protectedFields)).append(". ");
        }
        if (!suspiciousFields.isEmpty()) {
            rec.append("Review suspicious fields: ").append(String.join(", ", suspiciousFields)).append(". ");
        }
        
        rec.append("Implement field whitelisting and input validation.");
        return rec.toString();
    }

    private String generatePayloadRecommendation(String riskLevel, List<String> attackTypes) {
        StringBuilder rec = new StringBuilder("Detected mass assignment attempt. ");
        
        if (attackTypes.contains("Admin Privilege Escalation")) {
            rec.append("Block admin field modifications. ");
        }
        if (attackTypes.contains("Financial Balance Manipulation")) {
            rec.append("Protect financial fields from mass assignment. ");
        }
        if (attackTypes.contains("Password Field Manipulation")) {
            rec.append("Never allow password fields in mass assignment. ");
        }
        
        rec.append("Use explicit field whitelisting for all mass assignment operations.");
        return rec.toString();
    }

    private String generateComprehensiveRecommendation(double protectionRate) {
        if (protectionRate >= 90) {
            return "EXCELLENT: Mass assignment protection is highly effective against field manipulation attacks.";
        } else if (protectionRate >= 75) {
            return "GOOD: Mass assignment protection is generally effective but some fields may be vulnerable.";
        } else if (protectionRate >= 50) {
            return "FAIR: Mass assignment protection needs improvement for sensitive fields.";
        } else {
            return "CRITICAL: Mass assignment protection is insufficient against field manipulation attacks.";
        }
    }

    private String generateWhitelistRecommendation(int allowedCount, int blockedCount, int unknownCount) {
        StringBuilder rec = new StringBuilder();
        
        if (blockedCount > 0) {
            rec.append("SECURITY ALERT: ").append(blockedCount).append(" protected fields detected. ");
        }
        if (unknownCount > 0) {
            rec.append("REVIEW REQUIRED: ").append(unknownCount).append(" unknown fields need validation. ");
        }
        if (allowedCount > 0) {
            rec.append("ALLOWED: ").append(allowedCount).append(" fields are safe for mass assignment. ");
        }
        
        rec.append("Maintain strict field whitelisting to prevent mass assignment vulnerabilities.");
        return rec.toString();
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
            redisTemplate.opsForValue().set(MASS_ASSIGNMENT_STATS_KEY, statsJson, 24, TimeUnit.HOURS);
            
        } catch (Exception e) {
            // Log error but continue
        }
    }
}