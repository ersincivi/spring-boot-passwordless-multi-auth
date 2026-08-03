package io.github.ersincivi.passwordless.controller.web;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import io.micrometer.core.instrument.MeterRegistry;
import io.swagger.v3.oas.annotations.Hidden;

/**
 * Public monitoring endpoints as documented in MONITORING_GUIDE.md
 * These endpoints provide the /monitor/* paths mentioned in the documentation.
 * 
 * NOTE: Hidden from Swagger/OpenAPI as these are internal monitoring endpoints.
 */
@Controller
@RequestMapping("/monitor")
@Hidden
public class MonitoringController {

    // TODO: Spring Boot 4 - Re-enable healthEndpoint
    // private final HealthEndpoint healthEndpoint;
    private final MeterRegistry meterRegistry;

    public MonitoringController(
            // HealthEndpoint healthEndpoint,
            MeterRegistry meterRegistry) {
        // this.healthEndpoint = healthEndpoint;
        this.meterRegistry = meterRegistry;
    }

    /**
     * Basic health check for load balancers
     * Public endpoint as documented
     */
    @GetMapping("/health")
    @ResponseBody
    public Map<String, Object> health() {
        Map<String, Object> health = new HashMap<>();
        try {
            // TODO: Spring Boot 4 - Re-enable healthEndpoint
            // var healthInfo = healthEndpoint.health();
            // health.put("status", healthInfo.getStatus().getCode());
            health.put("status", "UP");
            health.put("timestamp", System.currentTimeMillis());
        } catch (Exception e) {
            health.put("status", "DOWN");
            health.put("error", e.getMessage());
        }
        return health;
    }

    /**
     * Kubernetes liveness probe
     * Public endpoint as documented
     */
    @GetMapping("/liveness")
    @ResponseBody
    public Map<String, String> liveness() {
        Map<String, String> liveness = new HashMap<>();
        liveness.put("status", "UP");
        liveness.put("timestamp", String.valueOf(System.currentTimeMillis()));
        return liveness;
    }

    /**
     * Kubernetes readiness probe
     * Public endpoint as documented
     */
    @GetMapping("/readiness")
    @ResponseBody
    public Map<String, String> readiness() {
        Map<String, String> readiness = new HashMap<>();
        // Simple readiness check - could be enhanced with component checks
        readiness.put("status", "UP");
        readiness.put("timestamp", String.valueOf(System.currentTimeMillis()));
        return readiness;
    }

    /**
     * Detailed health monitoring
     * Requires ADMIN or SERVICE role as documented
     */
    @GetMapping("/health/detailed")
    @PreAuthorize("hasAnyRole('ADMIN', 'SERVICE')")
    @ResponseBody
    public Map<String, Object> detailedHealth() {
        Map<String, Object> detailed = new HashMap<>();
        try {
            // TODO: Spring Boot 4 - Re-enable healthEndpoint
            // var healthInfo = healthEndpoint.health();
            // detailed.put("status", healthInfo.getStatus().getCode());
            detailed.put("status", "UP");
            // Convert to map for safe serialization
            detailed.put("health", Map.of(
                "status", "UP",
                "description", "Health check available at /actuator/health"
            ));
            detailed.put("timestamp", System.currentTimeMillis());
        } catch (Exception e) {
            detailed.put("status", "DOWN");
            detailed.put("error", e.getMessage());
        }
        return detailed;
    }

    /**
     * Prometheus metrics endpoint as documented in MONITORING_GUIDE.md.
     * Access is enforced by the URL rule in SecurityConfig (T5.2:
     * MONITORING_TOKEN Bearer token OR an authenticated ADMIN) - a method-level
     * hasRole('ADMIN') here would override that rule and 403 the scraper.
     */
    @GetMapping(value = "/prometheus", produces = MediaType.TEXT_PLAIN_VALUE)
    public String prometheusMetrics() {
        // Redirect to actuator endpoint since we don't have direct PrometheusMeterRegistry access
        return "redirect:/actuator/prometheus";
    }

    /**
     * Metrics pointer endpoint. Same T5.2 access rule as /monitor/prometheus,
     * enforced at the URL level in SecurityConfig.
     */
    @GetMapping("/metrics")
    @ResponseBody
    public Map<String, Object> metrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("message", "Use /actuator/metrics for detailed metrics");
        metrics.put("prometheus", "Use /monitor/prometheus or /actuator/prometheus for Prometheus format");
        metrics.put("timestamp", System.currentTimeMillis());
        return metrics;
    }

    /**
     * API endpoints under /monitor/api/**
     * Requires ADMIN role as documented
     */
    @GetMapping("/api/status")
    @PreAuthorize("hasRole('ADMIN')")
    @ResponseBody
    public Map<String, Object> apiStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("status", "OK");
        status.put("endpoints", Map.of(
            "health", "/monitor/health",
            "liveness", "/monitor/liveness", 
            "readiness", "/monitor/readiness",
            "prometheus", "/monitor/prometheus",
            "detailed_health", "/monitor/health/detailed"
        ));
        status.put("timestamp", System.currentTimeMillis());
        return status;
    }
}