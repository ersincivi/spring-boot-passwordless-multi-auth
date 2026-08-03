package io.github.ersincivi.passwordless.config;

import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.boot.actuate.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Configuration for monitoring and actuator endpoints.
 * Provides secure information exposure while maintaining operational visibility.
 */
@Configuration
public class MonitoringConfig {

    private final Environment environment;

    public MonitoringConfig(Environment environment) {
        this.environment = environment;
    }

    /**
     * Custom info contributor that provides safe application information
     * without exposing sensitive configuration details.
     */
    @Bean
    public InfoContributor customInfoContributor() {
        return new InfoContributor() {
            @Override
            public void contribute(Info.Builder builder) {
                // Safe application information
                builder.withDetail("app", java.util.Map.of(
                    "name", "passwordless",
                    "version", "0.0.1",
                    "description", "Passwordless Multi-Auth Project",
                    "profile", getCurrentProfile(),
                    "startup-time", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
                ));
                
                // Runtime information (non-sensitive)
                builder.withDetail("runtime", java.util.Map.of(
                    "java-version", System.getProperty("java.version"),
                    "spring-boot-version", getSpringBootVersion(),
                    "timezone", System.getProperty("user.timezone")
                ));
                
                // Features status
                builder.withDetail("features", java.util.Map.of(
                    "remember-me", true,
                    "redis-sessions", true,
                    "oauth2", true,
                    "csrf-protection", true,
                    "rate-limiting", true
                ));
            }
        };
    }

    private String getCurrentProfile() {
        String[] profiles = environment.getActiveProfiles();
        return profiles.length > 0 ? profiles[0] : "default";
    }

    private String getSpringBootVersion() {
        try {
            return org.springframework.boot.SpringBootVersion.getVersion();
        } catch (Exception e) {
            return "unknown";
        }
    }
}