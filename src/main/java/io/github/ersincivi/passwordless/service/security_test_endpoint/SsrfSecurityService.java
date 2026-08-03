package io.github.ersincivi.passwordless.service.security_test_endpoint;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.ersincivi.passwordless.service.SecurityAuditService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.*;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Comprehensive SSRF (Server-Side Request Forgery) Security Service
 * Provides detection, prevention, and testing for SSRF attacks
 */
@Profile("dev") // Security test harness - dev profile only
@Service
public class SsrfSecurityService {

    private static final Logger log = LoggerFactory.getLogger(SsrfSecurityService.class);

    private static final String SSRF_STATS_KEY = "ssrf:statistics";
    private static final String SSRF_ATTEMPTS_KEY = "ssrf:attempts:";

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Autowired
    private SecurityAuditService securityAuditService;

    @Autowired
    private ObjectMapper objectMapper;

    // SSRF attack patterns
    private static final List<Pattern> SSRF_PATTERNS = Arrays.asList(
        // Private IP ranges (RFC 1918)
        Pattern.compile("^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)", Pattern.CASE_INSENSITIVE),
        
        // Localhost variations
        Pattern.compile("^(localhost|127\\.|0\\.0\\.0\\.0)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\b(0x7f|0177|2130706433|017700000001)\\b", Pattern.CASE_INSENSITIVE),
        
        // Link-local addresses
        Pattern.compile("^169\\.254\\.", Pattern.CASE_INSENSITIVE),
        
        // Multicast addresses  
        Pattern.compile("^22[4-9]\\.|^23[0-9]\\.", Pattern.CASE_INSENSITIVE),
        
        // Cloud metadata services
        Pattern.compile("169\\.254\\.169\\.254", Pattern.CASE_INSENSITIVE), // AWS metadata
        Pattern.compile("metadata\\.google\\.internal", Pattern.CASE_INSENSITIVE), // GCP metadata
        Pattern.compile("169\\.254\\.169\\.254:80", Pattern.CASE_INSENSITIVE),
        
        // Internal services
        Pattern.compile("\\b(admin|internal|private|test|staging|dev)\\.", Pattern.CASE_INSENSITIVE),
        
        // Protocol variations
        Pattern.compile("^(file|gopher|dict|ftp|sftp|ldap|jar)://", Pattern.CASE_INSENSITIVE),
        
        // URL encoding bypasses
        Pattern.compile("%2[eE]%2[eE]", Pattern.CASE_INSENSITIVE), // ../
        Pattern.compile("\\\\x[0-9a-fA-F]{2}", Pattern.CASE_INSENSITIVE), // Hex encoding
        
        // IPv6 localhost
        Pattern.compile("^\\[::\\]|^\\[::1\\]", Pattern.CASE_INSENSITIVE),
        
        // Port scanning indicators
        Pattern.compile(":[0-9]{1,5}(/|$)", Pattern.CASE_INSENSITIVE),
        
        // DNS rebinding attempts
        Pattern.compile("\\b[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}\\.", Pattern.CASE_INSENSITIVE)
    );

    // Allowed domains whitelist
    private static final Set<String> ALLOWED_DOMAINS = Set.of(
        "example.com",
        "httpbin.org",
        "jsonplaceholder.typicode.com",
        "api.github.com",
        "httpstat.us"
    );

    // Blocked ports (common internal services)
    private static final Set<Integer> BLOCKED_PORTS = Set.of(
        22,   // SSH
        23,   // Telnet  
        25,   // SMTP
        53,   // DNS
        110,  // POP3
        135,  // RPC
        139,  // NetBIOS
        143,  // IMAP
        161,  // SNMP
        445,  // SMB
        993,  // IMAPS
        995,  // POP3S
        1433, // MSSQL
        1521, // Oracle
        3306, // MySQL
        3389, // RDP
        5432, // PostgreSQL
        5984, // CouchDB
        6379, // Redis
        8585, // Common web
        9200, // Elasticsearch
        27017 // MongoDB
    );

    /**
     * Test URL for SSRF vulnerabilities
     */
    public Map<String, Object> testSsrfVulnerability(String targetUrl, String ipAddress, boolean logAttempt) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            // Analyze URL for SSRF patterns
            SsrfAnalysisResult analysis = analyzeUrlForSsrf(targetUrl);
            
            result.put("isVulnerable", analysis.isVulnerable());
            result.put("riskLevel", analysis.getRiskLevel());
            result.put("riskScore", analysis.getRiskScore());
            result.put("detectedPatterns", analysis.getDetectedPatterns());
            result.put("attackVectors", analysis.getAttackVectors());
            result.put("recommendation", analysis.getRecommendation());
            result.put("protectionStatus", analysis.isBlocked() ? "BLOCKED" : "ALLOWED");
            result.put("timestamp", LocalDateTime.now().toString());
            
            // Test URL resolution and accessibility
            UrlValidationResult urlValidation = validateUrl(targetUrl);
            result.put("urlValidation", urlValidation);
            
            // Update statistics
            updateSsrfStatistics(analysis.isVulnerable(), analysis.getRiskLevel(), ipAddress);
            
            // Log security event if requested
            if (logAttempt) {
                Map<String, Object> details = new HashMap<>();
                details.put("vulnerable", analysis.isVulnerable());
                details.put("riskLevel", analysis.getRiskLevel());
                details.put("attackVectors", analysis.getAttackVectors());
                details.put("targetUrl", targetUrl.length() > 100 ? targetUrl.substring(0, 100) + "..." : targetUrl);
                
                if (analysis.isVulnerable()) {
                    securityAuditService.logSecurityViolation(
                        "SYSTEM", "SSRF_VULNERABILITY_DETECTED", 
                        "SSRF vulnerability detected in target URL",
                        ipAddress, "SSRF_TESTING", details);
                } else {
                    securityAuditService.logAuthenticationEvent(
                        "SYSTEM", "SSRF_TEST_COMPLETED", "SUCCESS",
                        ipAddress, "SSRF_TESTING", details);
                }
            }
            
        } catch (Exception e) {
            result.put("error", "SSRF testing failed: " + e.getMessage());
            result.put("isVulnerable", false);
            result.put("riskLevel", "UNKNOWN");
        }
        
        return result;
    }

    /**
     * Perform comprehensive SSRF testing with multiple attack vectors
     */
    public Map<String, Object> performComprehensiveSsrfTest(String baseUrl, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        List<Map<String, Object>> testResults = new ArrayList<>();
        
        // Define SSRF test payloads
        List<String> ssrfPayloads = Arrays.asList(
            // Localhost variations
            "http://localhost:8585/admin",
            "http://127.0.0.1:6379/",
            "http://0.0.0.0:22/",
            "http://[::1]:3306/",
            
            // Private IP ranges
            "http://192.168.1.1/admin",
            "http://10.0.0.1/internal",
            "http://172.16.0.1:8585/",
            
            // Cloud metadata services
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            
            // Alternative protocols
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_FLUSHALL",
            "dict://localhost:11211/stats",
            "ftp://internal.example.com/",
            
            // URL encoding bypasses
            "http://127.0.0.1%2F:8585/",
            "http://localhost%2eexample%2ecom/",
            
            // Hex/Octal encoding
            "http://0x7f000001:8585/",
            "http://017700000001:22/",
            
            // Port scanning
            "http://target.com:22/",
            "http://target.com:3306/",
            "http://target.com:6379/",
            
            // DNS rebinding
            "http://127-0-0-1.example.com/",
            "http://localhost.example.com/",
            
            // IPv6 variations
            "http://[::]:8585/",
            "http://[0:0:0:0:0:0:0:1]:3306/"
        );
        
        int blockedCount = 0;
        int vulnerableCount = 0;
        
        for (int i = 0; i < ssrfPayloads.size(); i++) {
            String payload = ssrfPayloads.get(i);
            Map<String, Object> testResult = testSsrfVulnerability(payload, ipAddress, false);
            
            testResult.put("testId", "SSRF_" + (i + 1));
            testResult.put("payload", payload.length() > 100 ? payload.substring(0, 100) + "..." : payload);
            testResults.add(testResult);
            
            if ("BLOCKED".equals(testResult.get("protectionStatus"))) {
                blockedCount++;
            }
            if (Boolean.TRUE.equals(testResult.get("isVulnerable"))) {
                vulnerableCount++;
            }
        }
        
        // Calculate protection effectiveness
        double protectionRate = (double) blockedCount / ssrfPayloads.size() * 100;
        
        result.put("totalTests", ssrfPayloads.size());
        result.put("blockedAttacks", blockedCount);
        result.put("vulnerableTests", vulnerableCount);
        result.put("protectionRate", String.format("%.1f%%", protectionRate));
        result.put("effectivenessLevel", getEffectivenessLevel(protectionRate));
        result.put("testResults", testResults);
        result.put("timestamp", LocalDateTime.now().toString());
        result.put("recommendation", generateComprehensiveRecommendation(protectionRate, vulnerableCount));
        
        // Log comprehensive test
        Map<String, Object> testDetails = new HashMap<>();
        testDetails.put("totalTests", ssrfPayloads.size());
        testDetails.put("blockedCount", blockedCount);
        testDetails.put("vulnerableCount", vulnerableCount);
        testDetails.put("protectionRate", protectionRate);
        
        if (protectionRate < 90) {
            securityAuditService.logSecurityViolation(
                "SYSTEM", "SSRF_COMPREHENSIVE_TEST_LOW_PROTECTION", 
                String.format("SSRF comprehensive test completed with low protection rate: %.1f%%", protectionRate),
                ipAddress, "SSRF_TESTING", testDetails);
        } else {
            securityAuditService.logAuthenticationEvent(
                "SYSTEM", "SSRF_COMPREHENSIVE_TEST_COMPLETED", "SUCCESS",
                ipAddress, "SSRF_TESTING", testDetails);
        }
        
        return result;
    }

    /**
     * Test domain whitelist validation
     */
    public Map<String, Object> testDomainWhitelist(String targetUrl, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            boolean isWhitelisted = isDomainWhitelisted(targetUrl);
            boolean isValidFormat = isValidUrlFormat(targetUrl);
            
            result.put("isWhitelisted", isWhitelisted);
            result.put("isValidFormat", isValidFormat);
            result.put("allowed", isWhitelisted && isValidFormat);
            result.put("domain", extractDomain(targetUrl));
            result.put("allowedDomains", ALLOWED_DOMAINS);
            result.put("timestamp", LocalDateTime.now().toString());
            
            // Log domain validation test
            Map<String, Object> details = new HashMap<>();
            details.put("domain", extractDomain(targetUrl));
            details.put("whitelisted", isWhitelisted);
            details.put("validFormat", isValidFormat);
            
            securityAuditService.logAuthenticationEvent(
                "SYSTEM", "SSRF_DOMAIN_WHITELIST_TEST", "SUCCESS",
                ipAddress, "SSRF_TESTING", details);
            
        } catch (Exception e) {
            result.put("error", "Domain whitelist test failed: " + e.getMessage());
            result.put("allowed", false);
        }
        
        return result;
    }

    /**
     * Get SSRF attack statistics
     */
    public Map<String, Object> getSsrfStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        try {
            String statsJson = redisTemplate.opsForValue().get(SSRF_STATS_KEY);
            if (statsJson != null) {
                stats = objectMapper.readValue(statsJson, Map.class);
            }
        } catch (Exception e) {
            // Return empty stats if parsing fails
            stats.put("error", "Failed to retrieve statistics");
        }
        
        // Add default values if not present
        stats.putIfAbsent("totalTests", 0);
        stats.putIfAbsent("vulnerableTests", 0);
        stats.putIfAbsent("blockedTests", 0);
        stats.putIfAbsent("lastUpdated", LocalDateTime.now().toString());
        
        return stats;
    }

    // Private helper methods
    private SsrfAnalysisResult analyzeUrlForSsrf(String targetUrl) {
        SsrfAnalysisResult result = new SsrfAnalysisResult();
        List<String> detectedPatterns = new ArrayList<>();
        List<String> attackVectors = new ArrayList<>();
        int riskScore = 0;
        
        // Check for SSRF patterns
        for (Pattern pattern : SSRF_PATTERNS) {
            if (pattern.matcher(targetUrl).find()) {
                detectedPatterns.add(pattern.pattern());
                riskScore += 2;
                
                // Categorize attack vectors
                String patternStr = pattern.pattern();
                if (patternStr.contains("localhost|127\\.|0\\.0\\.0\\.0")) {
                    attackVectors.add("Localhost Access Attempt");
                } else if (patternStr.contains("10\\.|172\\.|192\\.168\\.")) {
                    attackVectors.add("Private Network Access");
                } else if (patternStr.contains("169\\.254\\.169\\.254")) {
                    attackVectors.add("Cloud Metadata Access");
                } else if (patternStr.contains("file|gopher|dict")) {
                    attackVectors.add("Alternative Protocol Access");
                } else if (patternStr.contains("%2")) {
                    attackVectors.add("URL Encoding Bypass");
                } else if (patternStr.contains("admin|internal|private")) {
                    attackVectors.add("Internal Service Access");
                }
            }
        }
        
        // Check for blocked ports
        try {
            URL url = new URL(targetUrl);
            int port = url.getPort();
            if (port != -1 && BLOCKED_PORTS.contains(port)) {
                riskScore += 3;
                attackVectors.add("Blocked Port Access: " + port);
            }
        } catch (MalformedURLException e) {
            riskScore += 1;
            attackVectors.add("Malformed URL");
        }
        
        // Check if domain is not whitelisted
        if (!isDomainWhitelisted(targetUrl)) {
            riskScore += 2;
            attackVectors.add("Non-whitelisted Domain");
        }
        
        boolean isVulnerable = riskScore > 3;
        String riskLevel = calculateRiskLevel(riskScore);
        
        result.setVulnerable(isVulnerable);
        result.setRiskScore(Math.min(riskScore, 10));
        result.setRiskLevel(riskLevel);
        result.setDetectedPatterns(detectedPatterns);
        result.setAttackVectors(attackVectors);
        result.setBlocked(isVulnerable); // Block if vulnerable
        result.setRecommendation(generateRecommendation(riskLevel, attackVectors));
        
        return result;
    }

    private UrlValidationResult validateUrl(String targetUrl) {
        UrlValidationResult result = new UrlValidationResult();
        
        try {
            URL url = new URL(targetUrl);
            result.setValidFormat(true);
            result.setProtocol(url.getProtocol());
            result.setHost(url.getHost());
            result.setPort(url.getPort());
            
            // Check if it's an IP address
            try {
                InetAddress.getByName(url.getHost());
                result.setIsIpAddress(true);
                
                // Check if it's a private IP
                InetAddress addr = InetAddress.getByName(url.getHost());
                result.setIsPrivateIp(addr.isSiteLocalAddress() || addr.isLoopbackAddress() || addr.isLinkLocalAddress());
                
            } catch (UnknownHostException e) {
                result.setIsIpAddress(false);
                result.setIsPrivateIp(false);
            }
            
            // Check protocol safety
            result.setIsSafeProtocol(url.getProtocol().equals("http") || url.getProtocol().equals("https"));
            
        } catch (MalformedURLException e) {
            result.setValidFormat(false);
            result.setError("Malformed URL: " + e.getMessage());
        }
        
        return result;
    }

    private boolean isDomainWhitelisted(String targetUrl) {
        try {
            String domain = extractDomain(targetUrl);
            return ALLOWED_DOMAINS.contains(domain);
        } catch (Exception e) {
            return false;
        }
    }

    private String extractDomain(String targetUrl) {
        try {
            URL url = new URL(targetUrl);
            return url.getHost().toLowerCase();
        } catch (MalformedURLException e) {
            return "";
        }
    }

    private boolean isValidUrlFormat(String targetUrl) {
        try {
            new URL(targetUrl);
            return true;
        } catch (MalformedURLException e) {
            return false;
        }
    }

    private String calculateRiskLevel(int riskScore) {
        if (riskScore >= 8) return "CRITICAL";
        if (riskScore >= 6) return "HIGH";
        if (riskScore >= 4) return "MEDIUM";
        if (riskScore >= 2) return "LOW";
        return "MINIMAL";
    }

    private String getEffectivenessLevel(double protectionRate) {
        if (protectionRate >= 95) return "EXCELLENT";
        if (protectionRate >= 85) return "GOOD";
        if (protectionRate >= 70) return "FAIR";
        if (protectionRate >= 50) return "POOR";
        return "CRITICAL";
    }

    private String generateRecommendation(String riskLevel, List<String> attackVectors) {
        StringBuilder recommendation = new StringBuilder();
        
        switch (riskLevel) {
            case "CRITICAL":
                recommendation.append("IMMEDIATE ACTION REQUIRED: Critical SSRF vulnerabilities detected. ");
                break;
            case "HIGH":
                recommendation.append("HIGH PRIORITY: Significant SSRF risks identified. ");
                break;
            case "MEDIUM":
                recommendation.append("MEDIUM PRIORITY: Moderate SSRF vulnerabilities found. ");
                break;
            case "LOW":
                recommendation.append("LOW PRIORITY: Minor SSRF indicators detected. ");
                break;
            default:
                recommendation.append("No significant SSRF vulnerabilities detected. ");
        }
        
        if (attackVectors.contains("Localhost Access Attempt")) {
            recommendation.append("Block localhost and 127.x.x.x access. ");
        }
        if (attackVectors.contains("Private Network Access")) {
            recommendation.append("Implement private IP range filtering. ");
        }
        if (attackVectors.contains("Cloud Metadata Access")) {
            recommendation.append("Block cloud metadata service endpoints. ");
        }
        if (attackVectors.contains("Alternative Protocol Access")) {
            recommendation.append("Restrict to HTTP/HTTPS protocols only. ");
        }
        
        recommendation.append("Use domain whitelisting and validate all external requests.");
        
        return recommendation.toString();
    }

    private String generateComprehensiveRecommendation(double protectionRate, int vulnerableCount) {
        StringBuilder recommendation = new StringBuilder();
        
        if (protectionRate >= 95) {
            recommendation.append("EXCELLENT: SSRF protection is highly effective. ");
        } else if (protectionRate >= 85) {
            recommendation.append("GOOD: SSRF protection is generally effective but has some gaps. ");
        } else if (protectionRate >= 70) {
            recommendation.append("FAIR: SSRF protection needs improvement. ");
        } else {
            recommendation.append("CRITICAL: SSRF protection is insufficient and requires immediate attention. ");
        }
        
        if (vulnerableCount > 0) {
            recommendation.append(String.format("%d vulnerable tests detected. ", vulnerableCount));
            recommendation.append("Implement URL validation, domain whitelisting, network segmentation, ");
            recommendation.append("and disable unnecessary protocols. ");
        }
        
        recommendation.append("Regularly test SSRF defenses and monitor outbound requests.");
        
        return recommendation.toString();
    }

    private void updateSsrfStatistics(boolean isVulnerable, String riskLevel, String ipAddress) {
        try {
            Map<String, Object> stats = getSsrfStatistics();
            
            int totalTests = (Integer) stats.getOrDefault("totalTests", 0) + 1;
            int vulnerableTests = (Integer) stats.getOrDefault("vulnerableTests", 0);
            int blockedTests = (Integer) stats.getOrDefault("blockedTests", 0);
            
            if (isVulnerable) {
                vulnerableTests++;
                blockedTests++; // Our system blocks vulnerable requests
            }
            
            stats.put("totalTests", totalTests);
            stats.put("vulnerableTests", vulnerableTests);
            stats.put("blockedTests", blockedTests);
            stats.put("protectionRate", String.format("%.1f%%", (double) blockedTests / totalTests * 100));
            stats.put("lastRiskLevel", riskLevel);
            stats.put("lastUpdated", LocalDateTime.now().toString());
            
            String statsJson = objectMapper.writeValueAsString(stats);
            redisTemplate.opsForValue().set(SSRF_STATS_KEY, statsJson, 24, TimeUnit.HOURS);
            
        } catch (Exception e) {
            // Log error but don't fail the main operation
            log.warn("Failed to update SSRF statistics: {}", e.getMessage());
        }
    }

    // Inner classes for analysis results
    private static class SsrfAnalysisResult {
        private boolean vulnerable;
        private int riskScore;
        private String riskLevel;
        private List<String> detectedPatterns;
        private List<String> attackVectors;
        private boolean blocked;
        private String recommendation;

        // Getters and setters
        public boolean isVulnerable() { return vulnerable; }
        public void setVulnerable(boolean vulnerable) { this.vulnerable = vulnerable; }
        
        public int getRiskScore() { return riskScore; }
        public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
        
        public String getRiskLevel() { return riskLevel; }
        public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
        
        public List<String> getDetectedPatterns() { return detectedPatterns; }
        public void setDetectedPatterns(List<String> detectedPatterns) { this.detectedPatterns = detectedPatterns; }
        
        public List<String> getAttackVectors() { return attackVectors; }
        public void setAttackVectors(List<String> attackVectors) { this.attackVectors = attackVectors; }
        
        public boolean isBlocked() { return blocked; }
        public void setBlocked(boolean blocked) { this.blocked = blocked; }
        
        public String getRecommendation() { return recommendation; }
        public void setRecommendation(String recommendation) { this.recommendation = recommendation; }
    }

    private static class UrlValidationResult {
        private boolean validFormat;
        private String protocol;
        private String host;
        private int port;
        private boolean isIpAddress;
        private boolean isPrivateIp;
        private boolean isSafeProtocol;
        private String error;

        // Getters and setters
        public boolean isValidFormat() { return validFormat; }
        public void setValidFormat(boolean validFormat) { this.validFormat = validFormat; }
        
        public String getProtocol() { return protocol; }
        public void setProtocol(String protocol) { this.protocol = protocol; }
        
        public String getHost() { return host; }
        public void setHost(String host) { this.host = host; }
        
        public int getPort() { return port; }
        public void setPort(int port) { this.port = port; }
        
        public boolean isIsIpAddress() { return isIpAddress; }
        public void setIsIpAddress(boolean isIpAddress) { this.isIpAddress = isIpAddress; }
        
        public boolean isIsPrivateIp() { return isPrivateIp; }
        public void setIsPrivateIp(boolean isPrivateIp) { this.isPrivateIp = isPrivateIp; }
        
        public boolean isIsSafeProtocol() { return isSafeProtocol; }
        public void setIsSafeProtocol(boolean isSafeProtocol) { this.isSafeProtocol = isSafeProtocol; }
        
        public String getError() { return error; }
        public void setError(String error) { this.error = error; }
    }
}