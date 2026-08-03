package io.github.ersincivi.passwordless.config;

// TODO: Spring Boot 4 - Actuator health indicators have been restructured
// import org.springframework.boot.actuate.health.Health;
// import org.springframework.boot.actuate.health.HealthIndicator;
// import org.springframework.boot.actuate.health.Status;
import java.sql.Connection;

import javax.sql.DataSource;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

/**
 * Custom health indicator that provides secure health information
 * without exposing sensitive internal details.
 */
// TODO: Spring Boot 4 - Actuator health indicators have been restructured
// @Component("application")
// public class CustomHealthIndicator implements HealthIndicator {
@Component
public class CustomHealthIndicator {

    private final DataSource dataSource;
    private final RedisTemplate<String, Object> redisTemplate;

    public CustomHealthIndicator(DataSource dataSource, RedisTemplate<String, Object> redisTemplate) {
        this.dataSource = dataSource;
        this.redisTemplate = redisTemplate;
    }

    // TODO: Spring Boot 4 - Re-enable HealthIndicator interface
    // @Override
    // public Health health() {
    //     try {
    //         // Check database connectivity
    //         boolean dbHealthy = checkDatabaseHealth();
    //         
    //         // Check Redis connectivity
    //         boolean redisHealthy = checkRedisHealth();
    //         
    //         // Determine overall health
    //         Status status = (dbHealthy && redisHealthy) ? Status.UP : Status.DOWN;
    //         
    //         Health.Builder builder = Health.status(status)
    //                 .withDetail("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME))
    //                 .withDetail("version", "1.0.0")
    //                 .withDetail("environment", "development"); // This should be dynamic in production
    //         
    //         // Add component status (but not detailed error information)
    //         if (dbHealthy) {
    //             builder.withDetail("database", "UP");
    //         } else {
    //             builder.withDetail("database", "DOWN");
    //         }
    //         
    //         if (redisHealthy) {
    //             builder.withDetail("cache", "UP");
    //         } else {
    //             builder.withDetail("cache", "DOWN");
    //         }
    //         
    //         return builder.build();
    //         
    //     } catch (Exception e) {
    //         return Health.down()
    //                 .withDetail("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME))
    //                 .withDetail("error", "Health check failed")
    //                 .build();
    //     }
    // }

    private boolean checkDatabaseHealth() {
        try (Connection connection = dataSource.getConnection()) {
            return connection.isValid(5); // 5 second timeout
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkRedisHealth() {
        try {
            redisTemplate.opsForValue().set("health:check", "ping");
            String result = (String) redisTemplate.opsForValue().get("health:check");
            redisTemplate.delete("health:check");
            return "ping".equals(result);
        } catch (Exception e) {
            return false;
        }
    }
}