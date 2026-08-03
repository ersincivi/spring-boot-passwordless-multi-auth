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
 * Comprehensive MIME Sniffing Security Service
 * Provides detection and testing for MIME Sniffing attacks and content type confusion
 */
@Profile("dev") // Security test harness - dev profile only
@Service
public class MimeSniffingSecurityService {

    private static final String MIME_SNIFFING_STATS_KEY = "mime_sniffing:statistics";

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Autowired
    private SecurityAuditService securityAuditService;

    @Autowired
    private ObjectMapper objectMapper;

    // MIME sniffing attack patterns
    private static final List<Pattern> MIME_SNIFFING_PATTERNS = Arrays.asList(
        // Polyglot file patterns (files that can be interpreted as multiple formats)
        Pattern.compile("GIF89a.*<script", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),
        Pattern.compile("\\x89PNG.*<script", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),
        Pattern.compile("JFIF.*<script", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),
        
        // HTML disguised as other formats
        Pattern.compile("<!DOCTYPE html>", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<html[^>]*>", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<script[^>]*>", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<iframe[^>]*>", Pattern.CASE_INSENSITIVE),
        
        // SVG with embedded scripts
        Pattern.compile("<svg[^>]*>.*<script", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),
        Pattern.compile("data:image/svg\\+xml.*<script", Pattern.CASE_INSENSITIVE),
        
        // CSS with JavaScript
        Pattern.compile("@import.*javascript:", Pattern.CASE_INSENSITIVE),
        Pattern.compile("expression\\s*\\(", Pattern.CASE_INSENSITIVE),
        Pattern.compile("behavior:\\s*url", Pattern.CASE_INSENSITIVE),
        
        // XML with scripts
        Pattern.compile("<\\?xml.*<script", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),
        
        // Data URLs with scripts
        Pattern.compile("data:text/html.*<script", Pattern.CASE_INSENSITIVE),
        Pattern.compile("data:application/.*<script", Pattern.CASE_INSENSITIVE),
        
        // File upload bypasses
        Pattern.compile("\\.php\\.", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\.asp\\.", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\.jsp\\.", Pattern.CASE_INSENSITIVE),
        
        // Content type confusion
        Pattern.compile("text/html.*image/", Pattern.CASE_INSENSITIVE),
        Pattern.compile("application/javascript.*image/", Pattern.CASE_INSENSITIVE)
    );

    // Safe MIME types whitelist
    private static final Set<String> SAFE_MIME_TYPES = Set.of(
        "text/plain",
        "image/jpeg",
        "image/png", 
        "image/gif",
        "image/webp",
        "application/pdf",
        "application/json",
        "text/css"
    );

    // Dangerous MIME types that should be blocked or carefully handled
    private static final Set<String> DANGEROUS_MIME_TYPES = Set.of(
        "text/html",
        "application/javascript",
        "application/x-javascript",
        "text/javascript",
        "application/xml",
        "text/xml",
        "image/svg+xml",
        "application/x-shockwave-flash"
    );

    /**
     * Analyze content for MIME sniffing vulnerabilities
     */
    public Map<String, Object> analyzeContent(String content, String declaredMimeType, String filename, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        List<String> detectedPatterns = new ArrayList<>();
        List<String> vulnerabilities = new ArrayList<>();
        int riskScore = 0;
        
        try {
            String detectedMimeType = detectActualMimeType(content, filename);
            boolean mimeTypeMismatch = !declaredMimeType.equals(detectedMimeType);
            
            // Check for MIME type mismatch
            if (mimeTypeMismatch) {
                riskScore += 4;
                vulnerabilities.add("MIME type mismatch: declared=" + declaredMimeType + ", detected=" + detectedMimeType);
            }
            
            // Check for polyglot files
            for (Pattern pattern : MIME_SNIFFING_PATTERNS) {
                if (pattern.matcher(content).find()) {
                    detectedPatterns.add(pattern.pattern());
                    riskScore += 3;
                }
            }
            
            // Check if declared type is dangerous
            if (DANGEROUS_MIME_TYPES.contains(declaredMimeType.toLowerCase())) {
                riskScore += 2;
                vulnerabilities.add("Dangerous MIME type declared: " + declaredMimeType);
            }
            
            // Check for content sniffing bypass attempts
            if (isContentSniffingBypass(content)) {
                riskScore += 5;
                vulnerabilities.add("Content sniffing bypass attempt detected");
            }
            
            // Check for file extension mismatch
            String expectedTypeFromExtension = getExpectedMimeTypeFromFilename(filename);
            if (expectedTypeFromExtension != null && !expectedTypeFromExtension.equals(declaredMimeType)) {
                riskScore += 2;
                vulnerabilities.add("File extension mismatch: expected=" + expectedTypeFromExtension);
            }
            
            boolean isVulnerable = riskScore >= 3;
            String riskLevel = calculateRiskLevel(riskScore);
            
            result.put("isVulnerable", isVulnerable);
            result.put("riskScore", Math.min(riskScore, 10));
            result.put("riskLevel", riskLevel);
            result.put("declaredMimeType", declaredMimeType);
            result.put("detectedMimeType", detectedMimeType);
            result.put("filename", filename);
            result.put("mimeTypeMismatch", mimeTypeMismatch);
            result.put("detectedPatterns", detectedPatterns);
            result.put("vulnerabilities", vulnerabilities);
            result.put("recommendation", generateRecommendation(riskLevel, vulnerabilities));
            result.put("timestamp", LocalDateTime.now().toString());
            
            updateStatistics(isVulnerable, riskLevel, ipAddress);
            
        } catch (Exception e) {
            result.put("error", "MIME sniffing analysis failed: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * Test specific MIME sniffing payload
     */
    public Map<String, Object> testMimeSniffingPayload(String payload, String mimeType, String filename, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            List<String> detectedPatterns = new ArrayList<>();
            List<String> attackTypes = new ArrayList<>();
            int riskScore = 0;
            
            // Analyze payload for MIME sniffing patterns
            for (Pattern pattern : MIME_SNIFFING_PATTERNS) {
                if (pattern.matcher(payload).find()) {
                    detectedPatterns.add(pattern.pattern());
                    riskScore += 2;
                }
            }
            
            // Categorize attack types
            if (payload.toLowerCase().contains("gif89a") && payload.toLowerCase().contains("<script")) {
                attackTypes.add("GIF Polyglot Attack");
                riskScore += 4;
            }
            if (payload.toLowerCase().contains("png") && payload.toLowerCase().contains("<script")) {
                attackTypes.add("PNG Polyglot Attack");
                riskScore += 4;
            }
            if (payload.toLowerCase().contains("<svg") && payload.toLowerCase().contains("<script")) {
                attackTypes.add("SVG XSS Attack");
                riskScore += 3;
            }
            if (payload.toLowerCase().contains("data:text/html")) {
                attackTypes.add("Data URL HTML Injection");
                riskScore += 3;
            }
            if (mimeType.toLowerCase().contains("image/") && payload.toLowerCase().contains("text/html")) {
                attackTypes.add("Content Type Confusion");
                riskScore += 2;
            }
            
            boolean isBlocked = riskScore >= 3;
            String riskLevel = calculateRiskLevel(riskScore);
            
            result.put("payload", payload.length() > 200 ? payload.substring(0, 200) + "..." : payload);
            result.put("mimeType", mimeType);
            result.put("filename", filename);
            result.put("isBlocked", isBlocked);
            result.put("riskScore", Math.min(riskScore, 10));
            result.put("riskLevel", riskLevel);
            result.put("detectedPatterns", detectedPatterns);
            result.put("attackTypes", attackTypes);
            result.put("recommendation", generatePayloadRecommendation(riskLevel, attackTypes));
            
        } catch (Exception e) {
            result.put("error", "Payload test failed: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * Perform comprehensive MIME sniffing testing
     */
    public Map<String, Object> performComprehensiveTest(String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        List<Map<String, Object>> testResults = new ArrayList<>();
        
        // Comprehensive test payloads for MIME sniffing
        Object[][] testPayloads = {
            {"GIF89a<script>alert('xss')</script>", "image/gif", "malicious.gif"},
            {"\\x89PNG\\r\\n\\x1a\\n<script>alert('png')</script>", "image/png", "evil.png"},
            {"<!DOCTYPE html><script>alert('html')</script>", "image/jpeg", "fake.jpg"},
            {"<svg onload=\"alert('svg')\"><script>alert('xss')</script></svg>", "image/svg+xml", "malicious.svg"},
            {"@import 'javascript:alert(\"css\")'", "text/css", "evil.css"},
            {"<?xml version=\"1.0\"?><script>alert('xml')</script>", "application/xml", "malicious.xml"},
            {"data:text/html,<script>alert('data')</script>", "text/plain", "data.txt"},
            {"<iframe src=\"javascript:alert('iframe')\"></iframe>", "text/plain", "iframe.txt"},
            {"GIF89a\\x00\\x00<html><script>alert('polyglot')</script></html>", "image/gif", "polyglot.gif"},
            {"JFIF<script>alert('jpeg')</script>", "image/jpeg", "script.jpg"},
            {"behavior:url(javascript:alert('css'))", "text/css", "behavior.css"},
            {"expression(alert('ie'))", "text/css", "expression.css"}
        };
        
        int totalTests = testPayloads.length;
        int blockedCount = 0;
        
        for (int i = 0; i < testPayloads.length; i++) {
            Object[] testData = testPayloads[i];
            String payload = (String) testData[0];
            String mimeType = (String) testData[1];
            String filename = (String) testData[2];
            
            Map<String, Object> testResult = testMimeSniffingPayload(payload, mimeType, filename, ipAddress);
            testResult.put("testId", "MIME_" + (i + 1));
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
     * Validate MIME type against whitelist
     */
    public Map<String, Object> validateMimeType(String mimeType, String content, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            boolean isSafe = SAFE_MIME_TYPES.contains(mimeType.toLowerCase());
            boolean isDangerous = DANGEROUS_MIME_TYPES.contains(mimeType.toLowerCase());
            boolean hasScriptContent = content != null && 
                (content.toLowerCase().contains("<script") || content.toLowerCase().contains("javascript:"));
            
            String recommendation;
            String action;
            
            if (isSafe && !hasScriptContent) {
                recommendation = "MIME type is safe and content appears clean";
                action = "ALLOW";
            } else if (isDangerous || hasScriptContent) {
                recommendation = "DANGEROUS: MIME type or content contains scripts";
                action = "BLOCK";
            } else {
                recommendation = "MIME type not in whitelist - requires additional validation";
                action = "VALIDATE";
            }
            
            result.put("mimeType", mimeType);
            result.put("isSafe", isSafe);
            result.put("isDangerous", isDangerous);
            result.put("hasScriptContent", hasScriptContent);
            result.put("recommendation", recommendation);
            result.put("action", action);
            result.put("timestamp", LocalDateTime.now().toString());
            
        } catch (Exception e) {
            result.put("error", "MIME type validation failed: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * Get MIME sniffing statistics
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        try {
            String statsJson = redisTemplate.opsForValue().get(MIME_SNIFFING_STATS_KEY);
            if (statsJson != null) {
                stats = objectMapper.readValue(statsJson, Map.class);
            }
        } catch (Exception e) {
            stats.put("error", "Failed to retrieve statistics");
        }
        
        stats.putIfAbsent("totalAnalyses", 0);
        stats.putIfAbsent("vulnerableContent", 0);
        stats.putIfAbsent("blockedContent", 0);
        stats.putIfAbsent("lastUpdated", LocalDateTime.now().toString());
        
        return stats;
    }

    // Private helper methods
    private String detectActualMimeType(String content, String filename) {
        if (content == null || content.isEmpty()) {
            return getExpectedMimeTypeFromFilename(filename);
        }
        
        // Simple MIME type detection based on content
        String lowerContent = content.toLowerCase().trim();
        
        if (lowerContent.startsWith("gif89a") || lowerContent.startsWith("gif87a")) {
            return "image/gif";
        }
        if (lowerContent.startsWith("\\x89png")) {
            return "image/png";
        }
        if (lowerContent.startsWith("<!doctype html") || lowerContent.startsWith("<html")) {
            return "text/html";
        }
        if (lowerContent.startsWith("<svg")) {
            return "image/svg+xml";
        }
        if (lowerContent.startsWith("<?xml")) {
            return "application/xml";
        }
        if (lowerContent.contains("jfif") || lowerContent.startsWith("\\xff\\xd8\\xff")) {
            return "image/jpeg";
        }
        
        return "application/octet-stream";
    }

    private String getExpectedMimeTypeFromFilename(String filename) {
        if (filename == null) return null;
        
        String extension = filename.toLowerCase().substring(filename.lastIndexOf('.') + 1);
        
        switch (extension) {
            case "gif": return "image/gif";
            case "png": return "image/png";
            case "jpg": case "jpeg": return "image/jpeg";
            case "svg": return "image/svg+xml";
            case "html": case "htm": return "text/html";
            case "css": return "text/css";
            case "js": return "application/javascript";
            case "xml": return "application/xml";
            case "pdf": return "application/pdf";
            case "txt": return "text/plain";
            default: return null;
        }
    }

    private boolean isContentSniffingBypass(String content) {
        return content.toLowerCase().contains("content-type:") ||
               content.toLowerCase().contains("x-content-type-options:") ||
               content.toLowerCase().matches(".*\\x00.*<script.*") ||
               content.toLowerCase().contains("/**/") && content.toLowerCase().contains("<script");
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
            "GIF Polyglot Attack",
            "PNG Script Injection",
            "HTML Disguised as JPEG",
            "SVG XSS Attack",
            "CSS Import JavaScript",
            "XML Script Injection",
            "Data URL HTML Attack",
            "Iframe JavaScript Injection",
            "GIF-HTML Polyglot",
            "JPEG Script Injection",
            "CSS Behavior Attack",
            "CSS Expression Attack"
        };
        return index < testNames.length ? testNames[index] : "Unknown MIME Test";
    }

    private String generateRecommendation(String riskLevel, List<String> vulnerabilities) {
        StringBuilder rec = new StringBuilder();
        
        switch (riskLevel) {
            case "CRITICAL":
                rec.append("IMMEDIATE ACTION: Critical MIME sniffing vulnerability detected. ");
                break;
            case "HIGH":
                rec.append("HIGH PRIORITY: MIME sniffing attack patterns found. ");
                break;
            case "MEDIUM":
                rec.append("MEDIUM PRIORITY: MIME type inconsistencies detected. ");
                break;
            default:
                rec.append("Monitor MIME types and content validation. ");
        }
        
        if (vulnerabilities.stream().anyMatch(v -> v.contains("mismatch"))) {
            rec.append("Implement strict MIME type validation. ");
        }
        if (vulnerabilities.stream().anyMatch(v -> v.contains("bypass"))) {
            rec.append("Enable X-Content-Type-Options: nosniff header. ");
        }
        if (vulnerabilities.stream().anyMatch(v -> v.contains("Dangerous"))) {
            rec.append("Block dangerous MIME types or sanitize content. ");
        }
        
        return rec.toString();
    }

    private String generatePayloadRecommendation(String riskLevel, List<String> attackTypes) {
        StringBuilder rec = new StringBuilder("Detected MIME sniffing attempt. ");
        
        if (attackTypes.contains("GIF Polyglot Attack") || attackTypes.contains("PNG Polyglot Attack")) {
            rec.append("Block polyglot files with embedded scripts. ");
        }
        if (attackTypes.contains("SVG XSS Attack")) {
            rec.append("Sanitize SVG files or serve with safe MIME type. ");
        }
        if (attackTypes.contains("Content Type Confusion")) {
            rec.append("Implement strict MIME type validation. ");
        }
        
        rec.append("Use X-Content-Type-Options: nosniff header.");
        return rec.toString();
    }

    private String generateComprehensiveRecommendation(double protectionRate) {
        if (protectionRate >= 90) {
            return "EXCELLENT: MIME sniffing protection is highly effective against content type confusion.";
        } else if (protectionRate >= 75) {
            return "GOOD: MIME sniffing protection is generally effective but some polyglots may bypass.";
        } else if (protectionRate >= 50) {
            return "FAIR: MIME sniffing protection needs improvement for advanced attacks.";
        } else {
            return "CRITICAL: MIME sniffing protection is insufficient against content type attacks.";
        }
    }

    private void updateStatistics(boolean vulnerable, String riskLevel, String ipAddress) {
        try {
            Map<String, Object> stats = getStatistics();
            
            int totalAnalyses = (Integer) stats.getOrDefault("totalAnalyses", 0) + 1;
            int vulnerableContent = (Integer) stats.getOrDefault("vulnerableContent", 0);
            int blockedContent = (Integer) stats.getOrDefault("blockedContent", 0);
            
            if (vulnerable) {
                vulnerableContent++;
                blockedContent++; // Our system blocks vulnerable content
            }
            
            stats.put("totalAnalyses", totalAnalyses);
            stats.put("vulnerableContent", vulnerableContent);
            stats.put("blockedContent", blockedContent);
            stats.put("protectionRate", String.format("%.1f%%", (double) blockedContent / totalAnalyses * 100));
            stats.put("lastRiskLevel", riskLevel);
            stats.put("lastUpdated", LocalDateTime.now().toString());
            
            String statsJson = objectMapper.writeValueAsString(stats);
            redisTemplate.opsForValue().set(MIME_SNIFFING_STATS_KEY, statsJson, 24, TimeUnit.HOURS);
            
        } catch (Exception e) {
            // Log error but continue
        }
    }
}