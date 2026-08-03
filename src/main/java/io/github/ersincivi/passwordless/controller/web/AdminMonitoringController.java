package io.github.ersincivi.passwordless.controller.web;

import java.sql.Connection;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.sql.DataSource;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import io.github.ersincivi.passwordless.monitoring.SystemMetricsService;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.search.Search;
import io.swagger.v3.oas.annotations.Hidden;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Advanced monitoring dashboard for administrators and service operators.
 * Provides comprehensive system metrics, health status, and operational insights.
 * 
 * NOTE: Hidden from Swagger/OpenAPI as these are internal monitoring endpoints.
 */
@Controller
@RequestMapping("/admin/monitoring")
@Hidden
public class AdminMonitoringController {

    private final SystemMetricsService systemMetricsService;
    // TODO: Spring Boot 4 - Re-enable actuator endpoints
    // private final HealthEndpoint healthEndpoint;
    // private final InfoEndpoint infoEndpoint;
    // private final MetricsEndpoint metricsEndpoint;
    private final MeterRegistry meterRegistry;
    private final DataSource dataSource;
    private final RedisTemplate<String, Object> redisTemplate;

    public AdminMonitoringController(
            SystemMetricsService systemMetricsService,
            // HealthEndpoint healthEndpoint,
            // InfoEndpoint infoEndpoint,
            // MetricsEndpoint metricsEndpoint,
            MeterRegistry meterRegistry,
            DataSource dataSource,
            RedisTemplate<String, Object> redisTemplate) {
        this.systemMetricsService = systemMetricsService;
        // this.healthEndpoint = healthEndpoint;
        // this.infoEndpoint = infoEndpoint;
        // this.metricsEndpoint = metricsEndpoint;
        this.meterRegistry = meterRegistry;
        this.dataSource = dataSource;
        this.redisTemplate = redisTemplate;
    }

    /**
     * Main monitoring dashboard
     */
    @GetMapping("/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public String monitoringDashboard(Model model) {
        model.addAttribute("pageTitle", "System Monitoring Dashboard");
        model.addAttribute("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        model.addAttribute("healthStatus", getHealthStatus());
        model.addAttribute("quickMetrics", getQuickMetrics());
        return "admin/monitoring/dashboard";
    }

    /**
     * System metrics page with detailed hardware information
     */
    @GetMapping("/system")
    @PreAuthorize("hasRole('ADMIN')")
    public String systemMetrics(Model model) {
        model.addAttribute("pageTitle", "System Metrics");
        model.addAttribute("systemMetrics", systemMetricsService.getSystemMetrics());
        model.addAttribute("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        return "admin/monitoring/system";
    }

    /**
     * Application metrics and performance data
     */
    @GetMapping("/application")
    @PreAuthorize("hasRole('ADMIN')")
    public String applicationMetrics(Model model) {
        model.addAttribute("pageTitle", "Application Metrics");
        model.addAttribute("appMetrics", getApplicationMetrics());
        model.addAttribute("performanceMetrics", getPerformanceMetrics());
        model.addAttribute("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        return "admin/monitoring/application";
    }

    /**
     * Health checks and component status
     */
    @GetMapping("/health")
    @PreAuthorize("hasAnyRole('ADMIN', 'SERVICE')")
    public String healthChecks(Model model) {
        model.addAttribute("pageTitle", "Health Monitoring");
        // TODO: Spring Boot 4 - Re-enable healthEndpoint
        // model.addAttribute("health", healthEndpoint.health());
        model.addAttribute("health", Map.of("status", "UP"));
        model.addAttribute("componentHealth", getComponentHealthDetails());
        model.addAttribute("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        return "admin/monitoring/health";
    }

    /**
     * Debug endpoint to check CSP headers
     */
    @GetMapping("/debug/headers")
    @PreAuthorize("hasRole('ADMIN')")
    @ResponseBody
    public Map<String, Object> debugHeaders(HttpServletRequest request, HttpServletResponse response) {
        Map<String, Object> debug = new HashMap<>();
        
        // Check what CSP header is being set
        debug.put("csp-header", response.getHeader("Content-Security-Policy"));
        debug.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        debug.put("request-headers", Collections.list(request.getHeaderNames())
            .stream()
            .collect(Collectors.toMap(
                name -> name, 
                name -> request.getHeader(name)
            )));
        
        return debug;
    }

    /**
     * Grafana-style metrics API endpoint for external monitoring tools
     */
    @GetMapping("/api/metrics")
    @PreAuthorize("hasRole('ADMIN')")
    @ResponseBody
    public Map<String, Object> getGrafanaMetrics() {
        Map<String, Object> grafanaData = new HashMap<>();
        
        // System metrics formatted for Grafana
        grafanaData.put("system", systemMetricsService.getSystemMetrics());
        grafanaData.put("application", getApplicationMetrics());
        grafanaData.put("health", getHealthStatus());
        grafanaData.put("performance", getPerformanceMetrics());
        grafanaData.put("timestamp", System.currentTimeMillis());
        
        return grafanaData;
    }

    /**
     * Prometheus metrics endpoint - redirects to actuator endpoint
     * Note: This endpoint is at /admin/monitoring/prometheus
     * For the documented /monitor/prometheus endpoint, see MonitoringController
     */
    @GetMapping("/prometheus")
    @PreAuthorize("hasRole('ADMIN')")
    public String prometheusMetrics() {
        // Redirect to the standard actuator Prometheus endpoint
        return "redirect:/actuator/prometheus";
    }

    /**
     * Real-time metrics API for dashboard updates
     */
    @GetMapping("/api/realtime")
    @PreAuthorize("hasAnyRole('ADMIN', 'SERVICE')")
    @ResponseBody
    public Map<String, Object> getRealTimeMetrics() {
        Map<String, Object> realTime = new HashMap<>();
        
        realTime.put("timestamp", System.currentTimeMillis());
        realTime.put("cpu", systemMetricsService.getCpuMetrics());
        realTime.put("memory", systemMetricsService.getMemoryMetrics());
        realTime.put("jvm", systemMetricsService.getJvmMetrics());
        realTime.put("health", getHealthStatus());
        realTime.put("activeConnections", getActiveConnections());
        
        return realTime;
    }

    // Helper methods

    private Map<String, Object> getHealthStatus() {
        Map<String, Object> health = new HashMap<>();
        try {
            // TODO: Spring Boot 4 - Re-enable healthEndpoint
            // var healthInfo = healthEndpoint.health();
            // health.put("status", healthInfo.getStatus().getCode());
            health.put("status", "UP");
            // Simple health status without detailed components
            health.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        } catch (Exception e) {
            health.put("status", "DOWN");
            health.put("error", e.getMessage());
        }
        return health;
    }

    private Map<String, Object> getQuickMetrics() {
        Map<String, Object> quick = new HashMap<>();
        
        // JVM metrics
        Runtime runtime = Runtime.getRuntime();
        quick.put("jvmMemoryUsage", Math.round((double)(runtime.totalMemory() - runtime.freeMemory()) / runtime.maxMemory() * 100));
        quick.put("jvmMemoryTotal", runtime.maxMemory() / 1024 / 1024); // MB
        
        // System metrics
        Map<String, Object> cpuMetrics = systemMetricsService.getCpuMetrics();
        quick.put("cpuCores", cpuMetrics.get("cores_logical"));
        
        Map<String, Object> memoryMetrics = systemMetricsService.getMemoryMetrics();
        quick.put("systemMemoryUsage", memoryMetrics.get("usage_percent"));
        
        // Application metrics
        quick.put("activeUsers", getActiveUserCount());
        quick.put("databaseConnections", getDatabaseConnectionCount());
        
        return quick;
    }

    private Map<String, Object> getApplicationMetrics() {
        Map<String, Object> appMetrics = new HashMap<>();
        
        // Micrometer metrics with error handling and size limits
        try {
            Collection<io.micrometer.core.instrument.Meter> allMeters = Search.in(meterRegistry).meters();
            int totalCount = allMeters.size();
            
            // Get limited available meters to prevent large responses
            List<String> meterNames = allMeters.stream()
                .map(meter -> meter.getId().getName())
                .distinct()
                .sorted()
                .limit(50) // Reduced limit for better performance
                .collect(Collectors.toList());
            
            appMetrics.put("availableMetrics", meterNames);
            appMetrics.put("totalMetricsCount", totalCount);
            appMetrics.put("metricsDisplayed", meterNames.size());
            
            // Add summary of metric types
            Map<String, Long> metricTypes = allMeters.stream()
                .collect(Collectors.groupingBy(
                    meter -> meter.getId().getType().toString(),
                    Collectors.counting()))
                .entrySet().stream()
                .limit(10) // Limit types shown
                .collect(Collectors.toMap(
                    Map.Entry::getKey,
                    Map.Entry::getValue));
            appMetrics.put("metricTypes", metricTypes);
            
        } catch (Exception e) {
            appMetrics.put("error", "Failed to retrieve Micrometer metrics: " + e.getMessage());
            appMetrics.put("availableMetrics", new ArrayList<>());
            appMetrics.put("totalMetricsCount", 0);
            appMetrics.put("metricsDisplayed", 0);
            appMetrics.put("metricTypes", new HashMap<>());
        }
        
        // Always provide basic metrics even if Micrometer fails
        try {
            appMetrics.put("httpRequests", getHttpRequestMetrics());
            appMetrics.put("databaseMetrics", getDatabaseMetrics());
            appMetrics.put("redisMetrics", getRedisMetrics());
        } catch (Exception e) {
            // Add fallback metrics if helpers fail
            appMetrics.put("httpRequests", Map.of("totalRequests", "N/A", "averageResponseTime", "N/A"));
            appMetrics.put("databaseMetrics", Map.of("activeConnections", "N/A", "maxConnections", "N/A"));
            appMetrics.put("redisMetrics", Map.of("operations", "N/A", "averageLatency", "N/A"));
        }
        
        return appMetrics;
    }

    private Map<String, Object> getPerformanceMetrics() {
        Map<String, Object> performance = new HashMap<>();
        
        // Response times, throughput, etc.
        performance.put("averageResponseTime", getAverageResponseTime());
        performance.put("requestsPerSecond", getRequestsPerSecond());
        performance.put("errorRate", getErrorRate());
        performance.put("uptime", getUptimeSeconds());
        
        return performance;
    }

    private Map<String, Object> getComponentHealthDetails() {
        Map<String, Object> components = new HashMap<>();
        
        // Database health
        components.put("database", checkDatabaseHealth());
        
        // Redis health
        components.put("redis", checkRedisHealth());
        
        // Disk space health
        components.put("diskSpace", checkDiskSpaceHealth());
        
        return components;
    }

    private Map<String, Object> checkDatabaseHealth() {
        Map<String, Object> dbHealth = new HashMap<>();
        try (Connection conn = dataSource.getConnection()) {
            boolean isValid = conn.isValid(5);
            dbHealth.put("status", isValid ? "UP" : "DOWN");
            dbHealth.put("responseTime", measureDatabaseResponseTime());
            dbHealth.put("activeConnections", getDatabaseConnectionCount());
        } catch (Exception e) {
            dbHealth.put("status", "DOWN");
            dbHealth.put("error", e.getMessage());
        }
        return dbHealth;
    }

    private Map<String, Object> checkRedisHealth() {
        Map<String, Object> redisHealth = new HashMap<>();
        try {
            long start = System.currentTimeMillis();
            redisTemplate.opsForValue().set("health:check", "ping");
            String result = (String) redisTemplate.opsForValue().get("health:check");
            long responseTime = System.currentTimeMillis() - start;
            redisTemplate.delete("health:check");
            
            redisHealth.put("status", "ping".equals(result) ? "UP" : "DOWN");
            redisHealth.put("responseTime", responseTime);
        } catch (Exception e) {
            redisHealth.put("status", "DOWN");
            redisHealth.put("error", e.getMessage());
        }
        return redisHealth;
    }

    private Map<String, Object> checkDiskSpaceHealth() {
        Map<String, Object> diskHealth = new HashMap<>();
        Map<String, Object> diskMetrics = systemMetricsService.getDiskMetrics();
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> filesystems = (List<Map<String, Object>>) diskMetrics.get("filesystems");
        
        boolean allHealthy = filesystems.stream()
            .allMatch(fs -> {
                Double usage = (Double) fs.get("usage_percent");
                return usage != null && usage < 90; // Less than 90% usage is healthy
            });
            
        diskHealth.put("status", allHealthy ? "UP" : "WARN");
        diskHealth.put("filesystems", filesystems);
        
        return diskHealth;
    }

    // Placeholder methods for metrics (would be implemented with actual metric collection)
    private int getActiveUserCount() { return 42; } // Would count active sessions
    private int getDatabaseConnectionCount() { return 8; } // Would query connection pool
    private int getActiveConnections() { return 15; } // Would count active HTTP connections
    private long measureDatabaseResponseTime() { return 12; } // Would measure actual DB response
    private boolean isHealthy() { return true; } // Would check overall health
    private double getAverageResponseTime() { return 125.5; } // Would calculate from metrics
    private double getRequestsPerSecond() { return 15.2; } // Would calculate from request counters
    private double getErrorRate() { return 0.1; } // Would calculate error percentage
    private long getUptimeSeconds() { return System.currentTimeMillis() / 1000; } // Application uptime

    private Map<String, Object> getHttpRequestMetrics() {
        // Would collect HTTP request metrics from Micrometer
        return Map.of("totalRequests", 1234, "averageResponseTime", 125.5);
    }

    private Map<String, Object> getDatabaseMetrics() {
        // Would collect database connection pool metrics
        return Map.of("activeConnections", 8, "maxConnections", 20);
    }

    private Map<String, Object> getRedisMetrics() {
        // Would collect Redis operation metrics
        return Map.of("operations", 567, "averageLatency", 2.1);
    }
}