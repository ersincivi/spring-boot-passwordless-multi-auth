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
 * Comprehensive Host Header Injection Security Service
 * Provides detection and testing for Host Header Injection attacks
 */
@Profile("dev") // Security test harness - dev profile only
@Service
public class HostHeaderInjectionSecurityService {

    private static final String HHI_STATS_KEY = "hhi:statistics";

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Autowired
    private SecurityAuditService securityAuditService;

    @Autowired
    private ObjectMapper objectMapper;

    // Allowed hosts (whitelist)
    private static final Set<String> ALLOWED_HOSTS = Set.of(
        "localhost",
        "127.0.0.1",
        "localhost:8585",
        "127.0.0.1:8585",
        "0:0:0:0:0:0:0:1",
        "[::1]"
    );

    // Host Header Injection attack patterns
    private static final List<Pattern> HHI_PATTERNS = Arrays.asList(
        // Malicious domains
        Pattern.compile("evil\\.com|attacker\\.com|malicious\\.org", Pattern.CASE_INSENSITIVE),
        
        // XSS in Host header
        Pattern.compile("<script|javascript:|onerror|onload", Pattern.CASE_INSENSITIVE),
        
        // Cache poisoning attempts
        Pattern.compile("cache[._-]poison|poison[._-]cache", Pattern.CASE_INSENSITIVE),
        
        // Password reset poisoning
        Pattern.compile("reset[._-]token|password[._-]reset", Pattern.CASE_INSENSITIVE),
        
        // Open redirect attempts
        Pattern.compile("redirect\\.to|goto\\.php|url=http", Pattern.CASE_INSENSITIVE),
        
        // Port scanning
        Pattern.compile(":\\d{1,5}$", Pattern.CASE_INSENSITIVE),
        
        // Internal IPs
        Pattern.compile("192\\.168\\.|10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.", Pattern.CASE_INSENSITIVE),
        
        // HTTP method injection
        Pattern.compile("GET\\s|POST\\s|PUT\\s|DELETE\\s", Pattern.CASE_INSENSITIVE),
        
        // Header injection
        Pattern.compile("\\r\\n|\\n\\r|%0d%0a|%0a%0d", Pattern.CASE_INSENSITIVE)
    );

    /**
     * Analyze request for Host Header Injection
     */
    public Map<String, Object> analyzeHostHeader(HttpServletRequest request, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        List<String> detectedPatterns = new ArrayList<>();
        List<String> suspiciousHosts = new ArrayList<>();
        int riskScore = 0;
        
        try {
            String hostHeader = request.getHeader("Host");
            String serverName = request.getServerName();
            int serverPort = request.getServerPort();
            
            if (hostHeader == null) {
                hostHeader = serverName + ":" + serverPort;
            }
            
            // Check if host is in whitelist
            boolean isWhitelisted = ALLOWED_HOSTS.contains(hostHeader.toLowerCase());
            
            if (!isWhitelisted) {
                riskScore += 3;
                suspiciousHosts.add("Non-whitelisted host: " + hostHeader);
            }
            
            // Analyze for attack patterns
            for (Pattern pattern : HHI_PATTERNS) {
                if (pattern.matcher(hostHeader).find()) {
                    detectedPatterns.add(pattern.pattern());
                    riskScore += 2;
                }
            }
            
            // Check for domain mismatch
            if (!hostHeader.toLowerCase().contains(serverName.toLowerCase())) {
                riskScore += 2;
                suspiciousHosts.add("Domain mismatch: " + hostHeader + " vs " + serverName);
            }
            
            boolean isVulnerable = riskScore >= 4;
            String riskLevel = calculateRiskLevel(riskScore);
            
            result.put("isVulnerable", isVulnerable);
            result.put("riskScore", Math.min(riskScore, 10));
            result.put("riskLevel", riskLevel);
            result.put("hostHeader", hostHeader);
            result.put("expectedHost", serverName + ":" + serverPort);
            result.put("isWhitelisted", isWhitelisted);
            result.put("detectedPatterns", detectedPatterns);
            result.put("suspiciousHosts", suspiciousHosts);
            result.put("recommendation", generateRecommendation(riskLevel, detectedPatterns));
            result.put("timestamp", LocalDateTime.now().toString());
            
            updateStatistics(isVulnerable, riskLevel, ipAddress);
            
        } catch (Exception e) {
            result.put("error", "Host header analysis failed: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * Test specific host header injection payload
     */
    public Map<String, Object> testHostHeaderPayload(String hostPayload, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            List<String> detectedPatterns = new ArrayList<>();
            int riskScore = 0;
            
            // Check against attack patterns
            for (Pattern pattern : HHI_PATTERNS) {
                if (pattern.matcher(hostPayload).find()) {
                    detectedPatterns.add(pattern.pattern());
                    riskScore += 2;
                }
            }
            
            // Check whitelist
            boolean isWhitelisted = ALLOWED_HOSTS.contains(hostPayload.toLowerCase());
            if (!isWhitelisted) {
                riskScore += 2;
            }
            
            boolean isVulnerable = riskScore >= 3;
            String riskLevel = calculateRiskLevel(riskScore);
            
            result.put("payload", hostPayload);
            result.put("isVulnerable", isVulnerable);
            result.put("riskScore", Math.min(riskScore, 10));
            result.put("riskLevel", riskLevel);
            result.put("isWhitelisted", isWhitelisted);
            result.put("detectedPatterns", detectedPatterns);
            result.put("recommendation", generateRecommendation(riskLevel, detectedPatterns));
            result.put("blocked", isVulnerable);
            
        } catch (Exception e) {
            result.put("error", "Payload test failed: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * Perform comprehensive Host Header Injection testing
     */
    public Map<String, Object> performComprehensiveTest(String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        List<Map<String, Object>> testResults = new ArrayList<>();
        
        // Test payloads for Host Header Injection
        String[] testPayloads = {
            "evil.com",
            "attacker.com:8585", 
            "localhost<script>alert('xss')</script>",
            "cache-poison.evil.com",
            "password-reset.attacker.com",
            "192.168.1.1",
            "10.0.0.1:3306",
            "localhost\r\nX-Injected: evil",
            "127.0.0.1%0d%0aSet-Cookie: evil=1",
            "redirect.to/evil.com"
        };
        
        int totalTests = testPayloads.length;
        int blockedCount = 0;
        
        for (int i = 0; i < testPayloads.length; i++) {
            Map<String, Object> testResult = testHostHeaderPayload(testPayloads[i], ipAddress);
            testResult.put("testId", "HHI_" + (i + 1));
            testResults.add(testResult);
            
            if ((Boolean) testResult.get("blocked")) {
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
     * Get Host Header Injection statistics
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        try {
            String statsJson = redisTemplate.opsForValue().get(HHI_STATS_KEY);
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

    private String generateRecommendation(String riskLevel, List<String> patterns) {
        StringBuilder rec = new StringBuilder();
        
        switch (riskLevel) {
            case "CRITICAL":
                rec.append("IMMEDIATE ACTION: Critical Host Header Injection detected. ");
                break;
            case "HIGH":
                rec.append("HIGH PRIORITY: Host Header Injection patterns found. ");
                break;
            case "MEDIUM":
                rec.append("MEDIUM PRIORITY: Suspicious host header detected. ");
                break;
            default:
                rec.append("Monitor host headers for injection attempts. ");
        }
        
        if (patterns.stream().anyMatch(p -> p.contains("script|javascript"))) {
            rec.append("Block XSS attempts in Host header. ");
        }
        if (patterns.stream().anyMatch(p -> p.contains("cache"))) {
            rec.append("Prevent cache poisoning attacks. ");
        }
        
        rec.append("Validate Host header against whitelist and reject suspicious requests.");
        return rec.toString();
    }

    private String generateComprehensiveRecommendation(double protectionRate) {
        if (protectionRate >= 90) {
            return "EXCELLENT: Host Header Injection protection is highly effective.";
        } else if (protectionRate >= 75) {
            return "GOOD: Host Header Injection protection is generally effective but has some gaps.";
        } else if (protectionRate >= 50) {
            return "FAIR: Host Header Injection protection needs improvement.";
        } else {
            return "CRITICAL: Host Header Injection protection is insufficient.";
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
            redisTemplate.opsForValue().set(HHI_STATS_KEY, statsJson, 24, TimeUnit.HOURS);
            
        } catch (Exception e) {
            // Log error but continue
        }
    }
}