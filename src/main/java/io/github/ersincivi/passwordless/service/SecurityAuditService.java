package io.github.ersincivi.passwordless.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.servlet.http.HttpServletRequest;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Comprehensive security audit logging service
 */
@Service
public class SecurityAuditService {
    
    private static final Logger auditLogger = LoggerFactory.getLogger("SECURITY_AUDIT");
    private static final Logger logger = LoggerFactory.getLogger(SecurityAuditService.class);
    
    @Autowired
    private StringRedisTemplate redisTemplate;
    
    @Autowired
    private ObjectMapper objectMapper;
    
    // Redis keys for audit logs
    private static final String AUDIT_LOG_KEY = "security_audit:";
    private static final String AUDIT_STATS_KEY = "security_stats:";
    
    // Log retention (7 days)
    private static final int LOG_RETENTION_DAYS = 7;
    
    /**
     * Log authentication events
     */
    public void logAuthenticationEvent(String username, String event, String result, 
                                     String ipAddress, String userAgent, Map<String, Object> details) {
        SecurityAuditEvent auditEvent = SecurityAuditEvent.builder()
            .eventId(generateEventId())
            .timestamp(LocalDateTime.now())
            .eventType("AUTHENTICATION")
            .eventAction(event)
            .result(result)
            .username(username)
            .ipAddress(ipAddress)
            .userAgent(userAgent)
            .details(details != null ? details : new HashMap<>())
            .severity(determineSeverity(event, result))
            .build();
            
        persistAuditEvent(auditEvent);
        logToFile(auditEvent);
        updateStatistics(auditEvent);
    }
    
    /**
     * Log session events
     */
    public void logSessionEvent(String username, String event, String sessionId, 
                               String ipAddress, Map<String, Object> details) {
        SecurityAuditEvent auditEvent = SecurityAuditEvent.builder()
            .eventId(generateEventId())
            .timestamp(LocalDateTime.now())
            .eventType("SESSION")
            .eventAction(event)
            .result("SUCCESS")
            .username(username)
            .sessionId(sessionId)
            .ipAddress(ipAddress)
            .details(details != null ? details : new HashMap<>())
            .severity("INFO")
            .build();
            
        persistAuditEvent(auditEvent);
        logToFile(auditEvent);
        updateStatistics(auditEvent);
    }
    
    /**
     * Log authorization events
     */
    public void logAuthorizationEvent(String username, String resource, String action, 
                                    String result, String ipAddress, Map<String, Object> details) {
        SecurityAuditEvent auditEvent = SecurityAuditEvent.builder()
            .eventId(generateEventId())
            .timestamp(LocalDateTime.now())
            .eventType("AUTHORIZATION")
            .eventAction(action)
            .result(result)
            .username(username)
            .resource(resource)
            .ipAddress(ipAddress)
            .details(details != null ? details : new HashMap<>())
            .severity("SUCCESS".equals(result) ? "INFO" : "WARN")
            .build();
            
        persistAuditEvent(auditEvent);
        logToFile(auditEvent);
        updateStatistics(auditEvent);
    }
    
    /**
     * Log account lockout events
     */
    public void logAccountLockoutEvent(String username, String event, String ipAddress, 
                                     int failedAttempts, Map<String, Object> details) {
        Map<String, Object> eventDetails = new HashMap<>(details != null ? details : new HashMap<>());
        eventDetails.put("failedAttempts", failedAttempts);
        
        SecurityAuditEvent auditEvent = SecurityAuditEvent.builder()
            .eventId(generateEventId())
            .timestamp(LocalDateTime.now())
            .eventType("ACCOUNT_LOCKOUT")
            .eventAction(event)
            .result("LOCKOUT_TRIGGERED".equals(event) ? "SUCCESS" : "INFO")
            .username(username)
            .ipAddress(ipAddress)
            .details(eventDetails)
            .severity("LOCKOUT_TRIGGERED".equals(event) ? "HIGH" : "MEDIUM")
            .build();
            
        persistAuditEvent(auditEvent);
        logToFile(auditEvent);
        updateStatistics(auditEvent);
    }
    
    /**
     * Log admin actions
     */
    public void logAdminAction(String adminUsername, String action, String targetResource, 
                              String result, String ipAddress, Map<String, Object> details) {
        SecurityAuditEvent auditEvent = SecurityAuditEvent.builder()
            .eventId(generateEventId())
            .timestamp(LocalDateTime.now())
            .eventType("ADMIN_ACTION")
            .eventAction(action)
            .result(result)
            .username(adminUsername)
            .resource(targetResource)
            .ipAddress(ipAddress)
            .details(details != null ? details : new HashMap<>())
            .severity("HIGH")
            .build();
            
        persistAuditEvent(auditEvent);
        logToFile(auditEvent);
        updateStatistics(auditEvent);
    }
    
    /**
     * Log security violations
     */
    public void logSecurityViolation(String username, String violationType, String description, 
                                   String ipAddress, String userAgent, Map<String, Object> details) {
        Map<String, Object> eventDetails = new HashMap<>(details != null ? details : new HashMap<>());
        eventDetails.put("violationType", violationType);
        eventDetails.put("description", description);
        
        SecurityAuditEvent auditEvent = SecurityAuditEvent.builder()
            .eventId(generateEventId())
            .timestamp(LocalDateTime.now())
            .eventType("SECURITY_VIOLATION")
            .eventAction(violationType)
            .result("BLOCKED")
            .username(username)
            .ipAddress(ipAddress)
            .userAgent(userAgent)
            .details(eventDetails)
            .severity("CRITICAL")
            .build();
            
        persistAuditEvent(auditEvent);
        logToFile(auditEvent);
        updateStatistics(auditEvent);
    }
    
    /**
     * Retrieve audit logs by criteria
     */
    public List<SecurityAuditEvent> getAuditLogs(String eventType, String username, 
                                                LocalDateTime startTime, LocalDateTime endTime, int limit) {
        List<SecurityAuditEvent> events = new ArrayList<>();
        
        try {
            String pattern = AUDIT_LOG_KEY + "*";
            Set<String> keys = redisTemplate.keys(pattern);
            
            if (keys != null) {
                for (String key : keys) {
                    String eventJson = redisTemplate.opsForValue().get(key);
                    if (eventJson != null) {
                        SecurityAuditEvent event = objectMapper.readValue(eventJson, SecurityAuditEvent.class);
                        
                        // Apply filters
                        if (matchesFilters(event, eventType, username, startTime, endTime)) {
                            events.add(event);
                        }
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Error retrieving audit logs", e);
        }
        
        // Sort by timestamp descending and limit results
        events.sort((a, b) -> b.getTimestamp().compareTo(a.getTimestamp()));
        return events.size() > limit ? events.subList(0, limit) : events;
    }
    
    /**
     * Get security statistics
     */
    public Map<String, Object> getSecurityStatistics(LocalDateTime startTime, LocalDateTime endTime) {
        Map<String, Object> stats = new HashMap<>();
        
        try {
            String statsKey = AUDIT_STATS_KEY + "daily:" + LocalDateTime.now().toLocalDate();
            String statsJson = redisTemplate.opsForValue().get(statsKey);
            
            if (statsJson != null) {
                stats = objectMapper.readValue(statsJson, HashMap.class);
            }
        } catch (Exception e) {
            logger.error("Error retrieving security statistics", e);
        }
        
        return stats;
    }
    
    /**
     * Helper method to extract client information from request
     */
    public Map<String, Object> extractRequestInfo(HttpServletRequest request) {
        Map<String, Object> info = new HashMap<>();
        
        if (request != null) {
            info.put("ipAddress", request.getRemoteAddr());
            info.put("userAgent", request.getHeader("User-Agent"));
            info.put("requestUri", request.getRequestURI());
            info.put("method", request.getMethod());
            info.put("sessionId", request.getSession(false) != null ? request.getSession().getId() : null);
            
            // Add headers for security analysis
            Map<String, String> headers = new HashMap<>();
            Enumeration<String> headerNames = request.getHeaderNames();
            while (headerNames.hasMoreElements()) {
                String headerName = headerNames.nextElement();
                headers.put(headerName, request.getHeader(headerName));
            }
            info.put("headers", headers);
        }
        
        return info;
    }
    
    private void persistAuditEvent(SecurityAuditEvent event) {
        try {
            String eventJson = objectMapper.writeValueAsString(event);
            String key = AUDIT_LOG_KEY + event.getEventId();
            
            redisTemplate.opsForValue().set(key, eventJson, LOG_RETENTION_DAYS, TimeUnit.DAYS);
        } catch (JsonProcessingException e) {
            logger.error("Error persisting audit event", e);
        }
    }
    
    private void logToFile(SecurityAuditEvent event) {
        auditLogger.info("AUDIT_EVENT: eventId={}, type={}, action={}, result={}, username={}, " +
                        "ip={}, severity={}, timestamp={}, details={}", 
                        event.getEventId(), event.getEventType(), event.getEventAction(), 
                        event.getResult(), event.getUsername(), event.getIpAddress(), 
                        event.getSeverity(), event.getTimestamp(), event.getDetails());
    }
    
    private void updateStatistics(SecurityAuditEvent event) {
        try {
            String statsKey = AUDIT_STATS_KEY + "daily:" + event.getTimestamp().toLocalDate();
            String statsJson = redisTemplate.opsForValue().get(statsKey);
            
            Map<String, Object> stats = new HashMap<>();
            if (statsJson != null) {
                stats = objectMapper.readValue(statsJson, HashMap.class);
            }
            
            // Update counters
            String eventKey = event.getEventType() + "_" + event.getResult();
            stats.put(eventKey, ((Integer) stats.getOrDefault(eventKey, 0)) + 1);
            stats.put("total_events", ((Integer) stats.getOrDefault("total_events", 0)) + 1);
            stats.put("last_updated", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            
            // Update severity counters
            String severityKey = "severity_" + event.getSeverity();
            stats.put(severityKey, ((Integer) stats.getOrDefault(severityKey, 0)) + 1);
            
            redisTemplate.opsForValue().set(statsKey, objectMapper.writeValueAsString(stats), 
                                          LOG_RETENTION_DAYS + 5, TimeUnit.DAYS);
        } catch (Exception e) {
            logger.error("Error updating security statistics", e);
        }
    }
    
    private String generateEventId() {
        return "SEC_" + System.currentTimeMillis() + "_" + UUID.randomUUID().toString().substring(0, 8);
    }
    
    private String determineSeverity(String event, String result) {
        if ("FAILED".equals(result)) {
            return "HIGH";
        } else if ("LOGIN_ATTEMPT".equals(event) || "LOGOUT".equals(event)) {
            return "INFO";
        } else if ("PASSWORD_CHANGE".equals(event)) {
            return "MEDIUM";
        }
        return "INFO";
    }
    
    private boolean matchesFilters(SecurityAuditEvent event, String eventType, String username, 
                                 LocalDateTime startTime, LocalDateTime endTime) {
        if (eventType != null && !eventType.equals(event.getEventType())) {
            return false;
        }
        if (username != null && !username.equals(event.getUsername())) {
            return false;
        }
        if (startTime != null && event.getTimestamp().isBefore(startTime)) {
            return false;
        }
        if (endTime != null && event.getTimestamp().isAfter(endTime)) {
            return false;
        }
        return true;
    }
    
    /**
     * Security Audit Event data class
     */
    public static class SecurityAuditEvent {
        private String eventId;
        private LocalDateTime timestamp;
        private String eventType;
        private String eventAction;
        private String result;
        private String username;
        private String ipAddress;
        private String userAgent;
        private String sessionId;
        private String resource;
        private Map<String, Object> details;
        private String severity;
        
        // Constructors
        public SecurityAuditEvent() {}
        
        private SecurityAuditEvent(Builder builder) {
            this.eventId = builder.eventId;
            this.timestamp = builder.timestamp;
            this.eventType = builder.eventType;
            this.eventAction = builder.eventAction;
            this.result = builder.result;
            this.username = builder.username;
            this.ipAddress = builder.ipAddress;
            this.userAgent = builder.userAgent;
            this.sessionId = builder.sessionId;
            this.resource = builder.resource;
            this.details = builder.details;
            this.severity = builder.severity;
        }
        
        public static Builder builder() {
            return new Builder();
        }
        
        // Builder pattern
        public static class Builder {
            private String eventId;
            private LocalDateTime timestamp;
            private String eventType;
            private String eventAction;
            private String result;
            private String username;
            private String ipAddress;
            private String userAgent;
            private String sessionId;
            private String resource;
            private Map<String, Object> details;
            private String severity;
            
            public Builder eventId(String eventId) { this.eventId = eventId; return this; }
            public Builder timestamp(LocalDateTime timestamp) { this.timestamp = timestamp; return this; }
            public Builder eventType(String eventType) { this.eventType = eventType; return this; }
            public Builder eventAction(String eventAction) { this.eventAction = eventAction; return this; }
            public Builder result(String result) { this.result = result; return this; }
            public Builder username(String username) { this.username = username; return this; }
            public Builder ipAddress(String ipAddress) { this.ipAddress = ipAddress; return this; }
            public Builder userAgent(String userAgent) { this.userAgent = userAgent; return this; }
            public Builder sessionId(String sessionId) { this.sessionId = sessionId; return this; }
            public Builder resource(String resource) { this.resource = resource; return this; }
            public Builder details(Map<String, Object> details) { this.details = details; return this; }
            public Builder severity(String severity) { this.severity = severity; return this; }
            
            public SecurityAuditEvent build() {
                return new SecurityAuditEvent(this);
            }
        }
        
        // Getters and setters
        public String getEventId() { return eventId; }
        public void setEventId(String eventId) { this.eventId = eventId; }
        
        public LocalDateTime getTimestamp() { return timestamp; }
        public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
        
        public String getEventType() { return eventType; }
        public void setEventType(String eventType) { this.eventType = eventType; }
        
        public String getEventAction() { return eventAction; }
        public void setEventAction(String eventAction) { this.eventAction = eventAction; }
        
        public String getResult() { return result; }
        public void setResult(String result) { this.result = result; }
        
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        
        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
        
        public String getUserAgent() { return userAgent; }
        public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
        
        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }
        
        public String getResource() { return resource; }
        public void setResource(String resource) { this.resource = resource; }
        
        public Map<String, Object> getDetails() { return details; }
        public void setDetails(Map<String, Object> details) { this.details = details; }
        
        public String getSeverity() { return severity; }
        public void setSeverity(String severity) { this.severity = severity; }
    }
}