package io.github.ersincivi.passwordless.config;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.config.MeterFilter;

/**
 * Advanced metrics configuration for comprehensive system monitoring.
 * Provides application metrics, custom counters, and performance monitoring.
 */
@Configuration
@EnableAspectJAutoProxy
public class MetricsConfig {
    
    // Application metrics counters
    private final AtomicInteger activeUsers = new AtomicInteger(0);
    private final AtomicInteger loginAttempts = new AtomicInteger(0);
    private final AtomicInteger securityEvents = new AtomicInteger(0);

    /**
     * Customize meter registry with application-specific tags
     */
    @Bean
    public MeterFilter metricsCommonTags() {
        return MeterFilter.commonTags(Arrays.asList(
            Tag.of("application", "passwordless"),
            Tag.of("version", "0.0.1"),
            Tag.of("environment", getEnvironment()),
            Tag.of("instance", getInstanceId())
        ));
    }

    /**
     * Application-specific metrics (non-conflicting with Spring Boot defaults)
     */
    @Bean
    public Gauge activeUsersGauge(MeterRegistry registry) {
        return Gauge.builder("application.users.active", activeUsers, AtomicInteger::get)
            .description("Number of active users")
            .register(registry);
    }
    
    @Bean
    public Counter loginAttemptsCounter(MeterRegistry registry) {
        return Counter.builder("application.login.attempts")
            .description("Total login attempts")
            .register(registry);
    }
    
    @Bean
    public Counter securityEventsCounter(MeterRegistry registry) {
        return Counter.builder("application.security.events")
            .description("Security-related events")
            .register(registry);
    }

    /**
     * System process metrics
     */
    @Bean
    public Gauge systemProcessUptimeGauge(MeterRegistry registry) {
        return Gauge.builder("system.process.uptime", this, m -> getProcessUptime())
            .description("Process uptime in milliseconds")
            .baseUnit("milliseconds")
            .register(registry);
    }

    /**
     * Database connection pool metrics
     */
    @Bean
    public Counter databaseConnectionCounter(MeterRegistry registry) {
        return Counter.builder("database.connections.created")
            .description("Database connections created")
            .register(registry);
    }

    /**
     * Redis operation metrics
     */
    @Bean
    public Timer redisOperationTimer(MeterRegistry registry) {
        return Timer.builder("redis.operations")
            .description("Redis operation execution time")
            .register(registry);
    }

    /**
     * Security metrics
     */
    @Bean
    public Counter securityEventCounter(MeterRegistry registry) {
        return Counter.builder("security.events")
            .description("Security events counter")
            .register(registry);
    }

    // Helper methods
    private String getEnvironment() {
        return System.getProperty("spring.profiles.active", "development");
    }

    private String getInstanceId() {
        return System.getProperty("instance.id", "secure-001");
    }

    private long getProcessUptime() {
        return System.currentTimeMillis();
    }

    // Metric accessor methods for other components
    public void incrementActiveUsers() {
        activeUsers.incrementAndGet();
    }

    public void decrementActiveUsers() {
        activeUsers.decrementAndGet();
    }

    public void incrementLoginAttempts() {
        loginAttempts.incrementAndGet();
    }

    public void incrementSecurityEvents() {
        securityEvents.incrementAndGet();
    }
}