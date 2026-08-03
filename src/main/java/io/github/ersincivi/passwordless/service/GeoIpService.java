package io.github.ersincivi.passwordless.service;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CountryResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.util.Optional;

@Service
public class GeoIpService {

    private static final Logger logger = LoggerFactory.getLogger(GeoIpService.class);
    
    private final ResourceLoader resourceLoader;
    private DatabaseReader databaseReader;
    
    @Value("${app.geoip.database}")
    private String dbPath;
    
    @Value("${app.geoip.enabled:true}")
    private boolean geoipEnabled;

    public GeoIpService(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }
    
    @PostConstruct
    public void initializeDatabase() {
        if (!geoipEnabled) {
            logger.info("GeoIP service is disabled via configuration");
            return;
        }
        
        if (dbPath == null || dbPath.isBlank()) {
            logger.warn("GeoIP database path not configured. GeoIP service will not be available.");
            return;
        }
        
        try {
            if (dbPath.startsWith("classpath:")) {
                // Load from classpath
                logger.info("Loading GeoIP database from classpath: {}", dbPath);
                Resource resource = resourceLoader.getResource(dbPath);
                if (!resource.exists()) {
                    logger.error("GeoIP database not found at classpath location: {}", dbPath);
                    return;
                }
                
                try (InputStream inputStream = resource.getInputStream()) {
                    this.databaseReader = new DatabaseReader.Builder(inputStream).build();
                    logger.info("Successfully loaded GeoIP database from classpath: {}", dbPath);
                }
            } else {
                // Load from file system
                logger.info("Loading GeoIP database from file system: {}", dbPath);
                File database = new File(dbPath);
                if (!database.exists()) {
                    logger.error("GeoIP database file not found: {}", dbPath);
                    return;
                }
                
                this.databaseReader = new DatabaseReader.Builder(database).build();
                logger.info("Successfully loaded GeoIP database from file: {}", dbPath);
            }
        } catch (IOException e) {
            logger.error("Failed to initialize GeoIP database from: {}. Error: {}", dbPath, e.getMessage(), e);
            this.databaseReader = null;
        }
    }

    public Optional<String> lookupCountryIso(String ip) {
        if (!geoipEnabled) {
            logger.debug("GeoIP service is disabled");
            return Optional.empty();
        }
        
        if (databaseReader == null) {
            logger.debug("GeoIP database not available for lookup");
            return Optional.empty();
        }
        
        if (ip == null || ip.isBlank()) {
            logger.debug("Invalid IP address provided for GeoIP lookup: {}", ip);
            return Optional.empty();
        }
        
        // Handle localhost and private IPs
        if (isLocalOrPrivateIP(ip)) {
            logger.debug("Local or private IP detected, returning default country: {}", ip);
            return Optional.of("US"); // Default for development/testing
        }
        
        try {
            InetAddress ipAddress = InetAddress.getByName(ip);
            CountryResponse response = databaseReader.country(ipAddress);
            
            if (response != null && response.getCountry() != null) {
                String countryCode = response.getCountry().getIsoCode();
                logger.debug("GeoIP lookup successful for IP: {} -> Country: {}", ip, countryCode);
                return Optional.ofNullable(countryCode);
            } else {
                logger.debug("No country information found for IP: {}", ip);
                return Optional.empty();
            }
        } catch (IOException | GeoIp2Exception e) {
            logger.debug("GeoIP lookup failed for IP: {}. Error: {}", ip, e.getMessage());
            return Optional.empty();
        }
    }
    
    /**
     * Check if the IP is a local or private IP address
     */
    private boolean isLocalOrPrivateIP(String ip) {
        if (ip == null || ip.isBlank()) {
            return true;
        }
        
        // Common localhost addresses
        if ("127.0.0.1".equals(ip) || "::1".equals(ip) || "localhost".equals(ip)) {
            return true;
        }
        
        try {
            InetAddress inetAddress = InetAddress.getByName(ip);
            return inetAddress.isLoopbackAddress() || 
                   inetAddress.isLinkLocalAddress() || 
                   inetAddress.isSiteLocalAddress() ||
                   inetAddress.isAnyLocalAddress();
        } catch (Exception e) {
            logger.debug("Error checking if IP is private: {}", ip, e);
            return true; // Assume private if we can't determine
        }
    }
    
    /**
     * Check if GeoIP service is available and properly initialized
     */
    public boolean isAvailable() {
        return geoipEnabled && databaseReader != null;
    }
    
    /**
     * Get service status information for debugging
     */
    public String getStatus() {
        if (!geoipEnabled) {
            return "GeoIP service disabled via configuration";
        }
        if (databaseReader == null) {
            return "GeoIP database not loaded (path: " + dbPath + ")";
        }
        return "GeoIP service active with database: " + dbPath;
    }
}


