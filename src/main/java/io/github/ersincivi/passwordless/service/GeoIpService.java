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

    @Value("${app.geoip.auto-download:true}")
    private boolean autoDownload;

    @Value("${app.geoip.download-url:https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-City.mmdb}")
    private String downloadUrl;

    @Value("${app.geoip.download-path:./data/GeoLite2-City.mmdb}")
    private String downloadPath;

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
                Resource resource = resourceLoader.getResource(dbPath);
                if (resource.exists()) {
                    try (InputStream inputStream = resource.getInputStream()) {
                        this.databaseReader = new DatabaseReader.Builder(inputStream).build();
                        logger.info("Successfully loaded GeoIP database from classpath: {}", dbPath);
                    }
                    return;
                }
                // Not bundled - fall through to the local copy / auto-download
                loadOrDownloadLocalDatabase();
            } else {
                File database = new File(dbPath);
                if (database.exists()) {
                    this.databaseReader = new DatabaseReader.Builder(database).build();
                    logger.info("Successfully loaded GeoIP database from file: {}", dbPath);
                    return;
                }
                logger.warn("GeoIP database file not found: {}", dbPath);
                loadOrDownloadLocalDatabase();
            }
        } catch (IOException e) {
            logger.error("Failed to initialize GeoIP database from: {}. Error: {}", dbPath, e.getMessage(), e);
            this.databaseReader = null;
        }
    }

    /**
     * First-run convenience: if no database was found at the configured
     * location, use (or fetch) a local copy under ./data. Keeps the app fully
     * usable without a manual MaxMind download; failures only disable geo
     * alerts, never the application.
     */
    private void loadOrDownloadLocalDatabase() throws IOException {
        File local = new File(downloadPath);

        if (!local.exists()) {
            if (!autoDownload) {
                logger.warn("GeoLite2 database is not installed and auto-download is disabled. "
                        + "Geo-location alerts will be inactive. Set GEOIP_DATABASE_PATH to a "
                        + "downloaded GeoLite2-City.mmdb to enable them.");
                return;
            }

            logger.info("GeoLite2 database is not installed locally - downloading it now (first run only)...");
            logger.info("Fetching GeoLite2-City.mmdb (~60 MB) from {} into {}", downloadUrl, downloadPath);

            try {
                java.nio.file.Path target = local.toPath();
                if (target.getParent() != null) {
                    java.nio.file.Files.createDirectories(target.getParent());
                }
                java.nio.file.Path temp = java.nio.file.Files.createTempFile(
                        target.getParent() != null ? target.getParent() : java.nio.file.Path.of("."),
                        "GeoLite2-City", ".mmdb.part");

                java.net.http.HttpClient client = java.net.http.HttpClient.newBuilder()
                        .followRedirects(java.net.http.HttpClient.Redirect.ALWAYS)
                        .connectTimeout(java.time.Duration.ofSeconds(20))
                        .build();
                java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(downloadUrl))
                        .timeout(java.time.Duration.ofMinutes(5))
                        .build();
                java.net.http.HttpResponse<java.nio.file.Path> response = client.send(request,
                        java.net.http.HttpResponse.BodyHandlers.ofFile(temp));

                if (response.statusCode() != 200) {
                    java.nio.file.Files.deleteIfExists(temp);
                    logger.warn("GeoLite2 download failed (HTTP {}). Geo-location alerts will be "
                            + "inactive until a database is provided.", response.statusCode());
                    return;
                }

                java.nio.file.Files.move(temp, target,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                logger.info("GeoLite2 download complete: {} ({} MB)", downloadPath,
                        java.nio.file.Files.size(target) / (1024 * 1024));
            } catch (IOException | InterruptedException e) {
                if (e instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
                logger.warn("GeoLite2 download failed: {}. Geo-location alerts will be inactive "
                        + "until a database is provided.", e.getMessage());
                return;
            }
        }

        this.databaseReader = new DatabaseReader.Builder(local).build();
        logger.info("Successfully loaded GeoIP database from file: {}", downloadPath);
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


