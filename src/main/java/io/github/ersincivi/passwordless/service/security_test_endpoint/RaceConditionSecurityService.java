package io.github.ersincivi.passwordless.service.security_test_endpoint;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.ersincivi.passwordless.service.SecurityAuditService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

/**
 * Comprehensive Race Condition Security Service
 * Provides detection and testing for Race Condition attacks and concurrent access vulnerabilities
 */
@Profile("dev") // Security test harness - dev profile only
@Service
public class RaceConditionSecurityService {

    private static final String RACE_CONDITION_STATS_KEY = "race_condition:statistics";
    private static final String RACE_CONDITION_COUNTER_KEY = "race_condition:counter:";
    private static final String RACE_CONDITION_LOCK_KEY = "race_condition:lock:";
    
    @Autowired
    private StringRedisTemplate redisTemplate;

    @Autowired
    private SecurityAuditService securityAuditService;

    @Autowired
    private ObjectMapper objectMapper;

    private final ExecutorService executorService = Executors.newFixedThreadPool(20);
    private final Map<String, AtomicLong> operationCounters = new ConcurrentHashMap<>();

    // Race condition attack patterns
    private static final List<Pattern> RACE_CONDITION_PATTERNS = Arrays.asList(
        // Concurrent access patterns
        Pattern.compile("concurrent|parallel|thread|async", Pattern.CASE_INSENSITIVE),
        
        // Financial transaction patterns
        Pattern.compile("balance|transfer|withdraw|deposit|payment", Pattern.CASE_INSENSITIVE),
        Pattern.compile("credit|debit|fund|transaction", Pattern.CASE_INSENSITIVE),
        
        // Resource allocation patterns
        Pattern.compile("allocate|reserve|claim|acquire", Pattern.CASE_INSENSITIVE),
        Pattern.compile("limit|quota|capacity|resource", Pattern.CASE_INSENSITIVE),
        
        // Counter/sequence patterns
        Pattern.compile("increment|decrement|counter|sequence", Pattern.CASE_INSENSITIVE),
        Pattern.compile("next_id|auto_increment|serial", Pattern.CASE_INSENSITIVE),
        
        // State modification patterns
        Pattern.compile("status|state|flag|enable|disable", Pattern.CASE_INSENSITIVE),
        Pattern.compile("update|modify|change|set", Pattern.CASE_INSENSITIVE),
        
        // Authentication/session patterns
        Pattern.compile("login|logout|session|auth|verify", Pattern.CASE_INSENSITIVE),
        Pattern.compile("token|ticket|nonce|csrf", Pattern.CASE_INSENSITIVE),
        
        // File/database operations
        Pattern.compile("create|delete|write|read|lock", Pattern.CASE_INSENSITIVE),
        Pattern.compile("insert|update|delete|select", Pattern.CASE_INSENSITIVE),
        
        // Cache operations
        Pattern.compile("cache|store|retrieve|invalidate", Pattern.CASE_INSENSITIVE),
        
        // Admin/privileged operations
        Pattern.compile("admin|privilege|permission|grant", Pattern.CASE_INSENSITIVE)
    );

    // Vulnerable operation types
    private static final Set<String> VULNERABLE_OPERATIONS = Set.of(
        "balance_transfer", "user_creation", "password_reset", 
        "privilege_grant", "resource_allocation", "counter_increment",
        "session_creation", "file_upload", "data_modification",
        "cache_update", "token_generation", "permission_change"
    );

    /**
     * Analyze operation for race condition vulnerabilities
     */
    public Map<String, Object> analyzeOperation(String operationType, String operationData, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        List<String> detectedPatterns = new ArrayList<>();
        List<String> vulnerabilities = new ArrayList<>();
        int riskScore = 0;
        
        try {
            // Check for vulnerable operation types
            if (VULNERABLE_OPERATIONS.contains(operationType.toLowerCase())) {
                riskScore += 3;
                vulnerabilities.add("Vulnerable operation type: " + operationType);
            }
            
            // Analyze operation data for race condition patterns
            if (operationData != null) {
                for (Pattern pattern : RACE_CONDITION_PATTERNS) {
                    if (pattern.matcher(operationData).find()) {
                        detectedPatterns.add(pattern.pattern());
                        riskScore += 2;
                    }
                }
            }
            
            // Check for concurrent access patterns
            if (isConcurrentAccessVulnerable(operationType, operationData)) {
                riskScore += 4;
                vulnerabilities.add("Concurrent access vulnerability detected");
            }
            
            // Check for atomic operation requirements
            if (requiresAtomicOperation(operationType)) {
                riskScore += 3;
                vulnerabilities.add("Operation requires atomic execution protection");
            }
            
            // Check for state consistency requirements
            if (requiresStateConsistency(operationType)) {
                riskScore += 2;
                vulnerabilities.add("Operation requires state consistency protection");
            }
            
            boolean isVulnerable = riskScore >= 4;
            String riskLevel = calculateRiskLevel(riskScore);
            
            result.put("isVulnerable", isVulnerable);
            result.put("riskScore", Math.min(riskScore, 10));
            result.put("riskLevel", riskLevel);
            result.put("operationType", operationType);
            result.put("detectedPatterns", detectedPatterns);
            result.put("vulnerabilities", vulnerabilities);
            result.put("recommendation", generateRecommendation(riskLevel, vulnerabilities));
            result.put("timestamp", LocalDateTime.now().toString());
            
            updateStatistics(isVulnerable, riskLevel, ipAddress);
            
        } catch (Exception e) {
            result.put("error", "Race condition analysis failed: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * Test race condition with concurrent execution
     */
    public Map<String, Object> testRaceCondition(String operationType, int threadCount, int iterationsPerThread, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            String counterKey = RACE_CONDITION_COUNTER_KEY + operationType + ":" + System.currentTimeMillis();
            AtomicInteger successCount = new AtomicInteger(0);
            AtomicInteger errorCount = new AtomicInteger(0);
            List<String> errors = Collections.synchronizedList(new ArrayList<>());
            
            // Initialize counter
            redisTemplate.opsForValue().set(counterKey, "0");
            
            CountDownLatch latch = new CountDownLatch(threadCount);
            List<Future<Void>> futures = new ArrayList<>();
            
            // Create concurrent tasks
            for (int i = 0; i < threadCount; i++) {
                final int threadId = i;
                Future<Void> future = executorService.submit(() -> {
                    try {
                        for (int j = 0; j < iterationsPerThread; j++) {
                            try {
                                // Simulate race condition vulnerable operation
                                performRaceConditionVulnerableOperation(counterKey, operationType, threadId, j);
                                successCount.incrementAndGet();
                            } catch (Exception e) {
                                errorCount.incrementAndGet();
                                errors.add("Thread " + threadId + ", Iteration " + j + ": " + e.getMessage());
                            }
                        }
                    } finally {
                        latch.countDown();
                    }
                    return null;
                });
                futures.add(future);
            }
            
            // Wait for all threads to complete (with timeout)
            boolean completed = latch.await(30, TimeUnit.SECONDS);
            
            // Get final counter value
            String finalCounterValue = redisTemplate.opsForValue().get(counterKey);
            int actualCount = finalCounterValue != null ? Integer.parseInt(finalCounterValue) : 0;
            int expectedCount = threadCount * iterationsPerThread;
            
            // Calculate race condition impact
            int lostOperations = expectedCount - actualCount;
            double raceConditionRate = (double) lostOperations / expectedCount * 100;
            
            boolean raceConditionDetected = lostOperations > 0 || errorCount.get() > 0;
            String severity = calculateRaceConditionSeverity(raceConditionRate, errorCount.get());
            
            result.put("operationType", operationType);
            result.put("threadCount", threadCount);
            result.put("iterationsPerThread", iterationsPerThread);
            result.put("expectedCount", expectedCount);
            result.put("actualCount", actualCount);
            result.put("lostOperations", lostOperations);
            result.put("successfulOperations", successCount.get());
            result.put("errorCount", errorCount.get());
            result.put("raceConditionRate", String.format("%.2f%%", raceConditionRate));
            result.put("raceConditionDetected", raceConditionDetected);
            result.put("severity", severity);
            result.put("completed", completed);
            result.put("errors", errors.size() > 10 ? errors.subList(0, 10) : errors);
            result.put("recommendation", generateRaceConditionRecommendation(severity, raceConditionRate));
            
            // Cleanup
            redisTemplate.delete(counterKey);
            
        } catch (Exception e) {
            result.put("error", "Race condition test failed: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * Perform comprehensive race condition testing
     */
    public Map<String, Object> performComprehensiveTest(String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        List<Map<String, Object>> testResults = new ArrayList<>();
        
        // Comprehensive race condition test scenarios
        Object[][] testScenarios = {
            {"balance_transfer", 10, 5},    // 10 threads, 5 operations each
            {"user_creation", 8, 3},        // 8 threads, 3 operations each  
            {"counter_increment", 15, 10},   // 15 threads, 10 operations each
            {"session_creation", 12, 4},     // 12 threads, 4 operations each
            {"privilege_grant", 6, 2},       // 6 threads, 2 operations each
            {"file_upload", 8, 3},          // 8 threads, 3 operations each
            {"cache_update", 10, 6},        // 10 threads, 6 operations each
            {"token_generation", 12, 5},     // 12 threads, 5 operations each
            {"resource_allocation", 9, 4},   // 9 threads, 4 operations each
            {"data_modification", 11, 3}     // 11 threads, 3 operations each
        };
        
        int totalTests = testScenarios.length;
        int vulnerableTests = 0;
        
        for (int i = 0; i < testScenarios.length; i++) {
            Object[] testData = testScenarios[i];
            String operationType = (String) testData[0];
            int threadCount = (Integer) testData[1];
            int iterations = (Integer) testData[2];
            
            Map<String, Object> testResult = testRaceCondition(operationType, threadCount, iterations, ipAddress);
            testResult.put("testId", "RACE_" + (i + 1));
            testResult.put("testName", getTestName(i));
            testResults.add(testResult);
            
            if ((Boolean) testResult.get("raceConditionDetected")) {
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
     * Test atomic operation protection
     */
    public Map<String, Object> testAtomicOperation(String operationType, String resourceId, String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            String lockKey = RACE_CONDITION_LOCK_KEY + operationType + ":" + resourceId;
            
            // Test lock acquisition
            Boolean lockAcquired = redisTemplate.opsForValue().setIfAbsent(lockKey, "locked", 
                                                                           Duration.ofSeconds(10));
            
            if (lockAcquired != null && lockAcquired) {
                // Simulate atomic operation
                Thread.sleep(100); // Simulate processing time
                
                // Test concurrent access during lock
                boolean concurrentAccessBlocked = testConcurrentAccess(lockKey);
                
                // Release lock
                redisTemplate.delete(lockKey);
                
                result.put("lockAcquired", true);
                result.put("atomicProtection", concurrentAccessBlocked);
                result.put("recommendation", concurrentAccessBlocked ? 
                    "Atomic operation protection is working correctly" :
                    "WARNING: Concurrent access not properly blocked");
            } else {
                result.put("lockAcquired", false);
                result.put("atomicProtection", false);
                result.put("recommendation", "Lock acquisition failed - check for existing locks");
            }
            
            result.put("operationType", operationType);
            result.put("resourceId", resourceId);
            result.put("lockKey", lockKey);
            result.put("timestamp", LocalDateTime.now().toString());
            
        } catch (Exception e) {
            result.put("error", "Atomic operation test failed: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * Get race condition statistics
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        try {
            String statsJson = redisTemplate.opsForValue().get(RACE_CONDITION_STATS_KEY);
            if (statsJson != null) {
                stats = objectMapper.readValue(statsJson, Map.class);
            }
        } catch (Exception e) {
            stats.put("error", "Failed to retrieve statistics");
        }
        
        stats.putIfAbsent("totalAnalyses", 0);
        stats.putIfAbsent("vulnerableOperations", 0);
        stats.putIfAbsent("raceConditionsDetected", 0);
        stats.putIfAbsent("lastUpdated", LocalDateTime.now().toString());
        
        return stats;
    }

    // Private helper methods
    private void performRaceConditionVulnerableOperation(String counterKey, String operationType, int threadId, int iteration) {
        try {
            // Simulate non-atomic read-modify-write operation
            String currentValue = redisTemplate.opsForValue().get(counterKey);
            int current = currentValue != null ? Integer.parseInt(currentValue) : 0;
            
            // Simulate processing delay (makes race condition more likely)
            Thread.sleep(1);
            
            // Simulate different operation types
            int newValue = current;
            switch (operationType) {
                case "balance_transfer":
                    newValue = current + (threadId + 1) * 10; // Transfer amount
                    break;
                case "counter_increment":
                    newValue = current + 1;
                    break;
                case "user_creation":
                    newValue = current + 1; // User count
                    break;
                default:
                    newValue = current + 1;
            }
            
            // Non-atomic write (vulnerable to race conditions)
            redisTemplate.opsForValue().set(counterKey, String.valueOf(newValue));
            
        } catch (Exception e) {
            throw new RuntimeException("Operation failed: " + e.getMessage());
        }
    }

    private boolean testConcurrentAccess(String lockKey) {
        try {
            // Try to acquire lock from another thread
            Boolean concurrentLockAttempt = redisTemplate.opsForValue().setIfAbsent(lockKey + ":test", "test", 
                                                                                    Duration.ofSeconds(1));
            return concurrentLockAttempt == null || !concurrentLockAttempt; // Should fail if properly locked
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isConcurrentAccessVulnerable(String operationType, String operationData) {
        if (operationData == null) return false;
        
        String combined = (operationType + " " + operationData).toLowerCase();
        
        return combined.contains("read") && combined.contains("write") ||
               combined.contains("check") && combined.contains("update") ||
               combined.contains("get") && combined.contains("set") ||
               combined.contains("validate") && combined.contains("modify");
    }

    private boolean requiresAtomicOperation(String operationType) {
        return operationType.toLowerCase().contains("transfer") ||
               operationType.toLowerCase().contains("increment") ||
               operationType.toLowerCase().contains("balance") ||
               operationType.toLowerCase().contains("counter") ||
               operationType.toLowerCase().contains("allocation");
    }

    private boolean requiresStateConsistency(String operationType) {
        return operationType.toLowerCase().contains("session") ||
               operationType.toLowerCase().contains("user") ||
               operationType.toLowerCase().contains("privilege") ||
               operationType.toLowerCase().contains("permission") ||
               operationType.toLowerCase().contains("status");
    }

    private String calculateRiskLevel(int riskScore) {
        if (riskScore >= 8) return "CRITICAL";
        if (riskScore >= 6) return "HIGH";
        if (riskScore >= 4) return "MEDIUM";
        if (riskScore >= 2) return "LOW";
        return "MINIMAL";
    }

    private String calculateRaceConditionSeverity(double raceRate, int errorCount) {
        if (raceRate > 20 || errorCount > 10) return "CRITICAL";
        if (raceRate > 10 || errorCount > 5) return "HIGH";
        if (raceRate > 5 || errorCount > 0) return "MEDIUM";
        if (raceRate > 0) return "LOW";
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
            "Financial Balance Transfer Race",
            "Concurrent User Creation",
            "Counter Increment Race Condition",
            "Session Creation Conflicts", 
            "Privilege Grant Race Condition",
            "File Upload Conflicts",
            "Cache Update Race Condition",
            "Token Generation Race",
            "Resource Allocation Conflicts",
            "Data Modification Race"
        };
        return index < testNames.length ? testNames[index] : "Unknown Race Condition Test";
    }

    private String generateRecommendation(String riskLevel, List<String> vulnerabilities) {
        StringBuilder rec = new StringBuilder();
        
        switch (riskLevel) {
            case "CRITICAL":
                rec.append("IMMEDIATE ACTION: Critical race condition vulnerability detected. ");
                break;
            case "HIGH":
                rec.append("HIGH PRIORITY: Race condition patterns found. ");
                break;
            case "MEDIUM":
                rec.append("MEDIUM PRIORITY: Potential race condition vulnerability. ");
                break;
            default:
                rec.append("Monitor for race condition patterns. ");
        }
        
        if (vulnerabilities.stream().anyMatch(v -> v.contains("Concurrent access"))) {
            rec.append("Implement proper synchronization mechanisms. ");
        }
        if (vulnerabilities.stream().anyMatch(v -> v.contains("atomic"))) {
            rec.append("Use atomic operations or distributed locks. ");
        }
        if (vulnerabilities.stream().anyMatch(v -> v.contains("consistency"))) {
            rec.append("Ensure state consistency with proper locking. ");
        }
        
        return rec.toString();
    }

    private String generateRaceConditionRecommendation(String severity, double raceRate) {
        StringBuilder rec = new StringBuilder();
        
        switch (severity) {
            case "CRITICAL":
                rec.append("CRITICAL: Severe race condition detected (").append(String.format("%.1f%%", raceRate)).append(" data loss). ");
                rec.append("Implement distributed locking immediately. ");
                break;
            case "HIGH":
                rec.append("HIGH: Significant race condition detected. Use atomic operations. ");
                break;
            case "MEDIUM":
                rec.append("MEDIUM: Race condition detected. Implement proper synchronization. ");
                break;
            case "LOW":
                rec.append("LOW: Minor race condition. Consider optimistic locking. ");
                break;
            default:
                rec.append("No race condition detected. Current implementation is thread-safe. ");
        }
        
        return rec.toString();
    }

    private String generateComprehensiveRecommendation(double vulnerabilityRate) {
        if (vulnerabilityRate == 0) {
            return "EXCELLENT: No race conditions detected. All operations appear thread-safe.";
        } else if (vulnerabilityRate <= 20) {
            return "GOOD: Minimal race conditions detected. Review and fix identified vulnerabilities.";
        } else if (vulnerabilityRate <= 50) {
            return "FAIR: Moderate race conditions detected. Implement comprehensive synchronization.";
        } else {
            return "CRITICAL: High race condition vulnerability. Immediate action required for thread safety.";
        }
    }

    private void updateStatistics(boolean vulnerable, String riskLevel, String ipAddress) {
        try {
            Map<String, Object> stats = getStatistics();
            
            int totalAnalyses = (Integer) stats.getOrDefault("totalAnalyses", 0) + 1;
            int vulnerableOperations = (Integer) stats.getOrDefault("vulnerableOperations", 0);
            int raceConditionsDetected = (Integer) stats.getOrDefault("raceConditionsDetected", 0);
            
            if (vulnerable) {
                vulnerableOperations++;
                raceConditionsDetected++;
            }
            
            stats.put("totalAnalyses", totalAnalyses);
            stats.put("vulnerableOperations", vulnerableOperations);
            stats.put("raceConditionsDetected", raceConditionsDetected);
            stats.put("detectionRate", String.format("%.1f%%", (double) raceConditionsDetected / totalAnalyses * 100));
            stats.put("lastRiskLevel", riskLevel);
            stats.put("lastUpdated", LocalDateTime.now().toString());
            
            String statsJson = objectMapper.writeValueAsString(stats);
            redisTemplate.opsForValue().set(RACE_CONDITION_STATS_KEY, statsJson, 24, TimeUnit.HOURS);
            
        } catch (Exception e) {
            // Log error but continue
        }
    }
}