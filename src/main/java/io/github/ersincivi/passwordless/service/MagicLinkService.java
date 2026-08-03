package io.github.ersincivi.passwordless.service;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import io.github.ersincivi.passwordless.config.MagicLinkProperties;

/**
 * Service for managing MagicLink authentication tokens for WEB
 * Uses UUID v7 for token generation and Redis for storage
 */
@Service
public class MagicLinkService {

    private static final Logger log = LoggerFactory.getLogger(MagicLinkService.class);
    private static final String REDIS_KEY_PREFIX_WEB = "passwordless:magiclink:web:";
    private static final String REDIS_KEY_PREFIX_API = "passwordless:magiclink:api:";

    private final RedisTemplate<String, Object> redisTemplate;
    private final MagicLinkProperties magicLinkProperties;

    public MagicLinkService(@Qualifier("redisTemplate") RedisTemplate<String, Object> redisTemplate,
                           MagicLinkProperties magicLinkProperties) {
        this.redisTemplate = redisTemplate;
        this.magicLinkProperties = magicLinkProperties;
    }

    /**
     * Generate a UUID v7 token for WEB authentication
     * UUID v7 is time-ordered and suitable for database indexing
     */
    public String generateWebToken(String email) {
        // Generate UUID v7 (time-ordered UUID)
        String token = generateUuidV7();
        
        // Store in Redis with email as value
        String redisKey = REDIS_KEY_PREFIX_WEB + token;
        int ttlSeconds = magicLinkProperties.getWeb().getTtlSeconds();
        
        redisTemplate.opsForValue().set(redisKey, email, Duration.ofSeconds(ttlSeconds));
        
        log.info("Generated WEB MagicLink token for email: {} (TTL: {}s)", email, ttlSeconds);
        return token;
    }

    /**
     * Verify and consume a WEB MagicLink token
     * Returns the email if valid, null if invalid or expired
     */
    public String verifyAndConsumeWebToken(String token) {
        String redisKey = REDIS_KEY_PREFIX_WEB + token;
        Object value = redisTemplate.opsForValue().get(redisKey);
        
        if (value == null) {
            log.warn("Invalid or expired WEB MagicLink token: {}", token);
            return null;
        }
        
        String email = value.toString();
        
        // Delete token after use (one-time use)
        redisTemplate.delete(redisKey);
        
        log.info("Verified and consumed WEB MagicLink token for email: {}", email);
        return email;
    }

    /**
     * Generate a JWT token for API authentication (mobile apps)
     * JWT is self-contained and doesn't require Redis lookup
     */
    public String generateApiToken(String email) {
        // For API, we'll use JWT which is handled by JwtService
        // Store a reference in Redis for revocation capability
        String token = generateUuidV7(); // Use UUID v7 as JWT identifier
        
        String redisKey = REDIS_KEY_PREFIX_API + token;
        int ttlSeconds = magicLinkProperties.getApi().getTtlSeconds();
        
        redisTemplate.opsForValue().set(redisKey, email, Duration.ofSeconds(ttlSeconds));
        
        log.info("Generated API MagicLink token for email: {} (TTL: {}s)", email, ttlSeconds);
        return token;
    }

    /**
     * Verify and consume an API MagicLink token
     * Returns the email if valid, null if invalid or expired
     */
    public String verifyAndConsumeApiToken(String token) {
        String redisKey = REDIS_KEY_PREFIX_API + token;
        Object value = redisTemplate.opsForValue().get(redisKey);
        
        if (value == null) {
            log.warn("Invalid or expired API MagicLink token: {}", token);
            return null;
        }
        
        String email = value.toString();
        
        // Delete token after use (one-time use)
        redisTemplate.delete(redisKey);
        
        log.info("Verified and consumed API MagicLink token for email: {}", email);
        return email;
    }

    /**
     * Get TTL in seconds for WEB tokens
     */
    public int getWebTtlSeconds() {
        return magicLinkProperties.getWeb().getTtlSeconds();
    }

    /**
     * Get TTL in seconds for API tokens
     */
    public int getApiTtlSeconds() {
        return magicLinkProperties.getApi().getTtlSeconds();
    }

    /**
     * Generate UUID version 7 (time-ordered)
     * UUID v7 encodes a timestamp in the first 48 bits
     */
    private String generateUuidV7() {
        // Get current timestamp in milliseconds
        long timestamp = System.currentTimeMillis();
        
        // Generate random UUID
        UUID uuid = UUID.randomUUID();
        
        // Extract random bits from UUID
        long mostSigBits = uuid.getMostSignificantBits();
        long leastSigBits = uuid.getLeastSignificantBits();
        
        // Build UUID v7:
        // - First 48 bits: timestamp (milliseconds)
        // - Next 4 bits: version (0111 = 7)
        // - Next 12 bits: random
        // - Next 2 bits: variant (10)
        // - Last 62 bits: random
        
        // Timestamp in first 48 bits
        long uuidV7MostSigBits = (timestamp << 16) & 0xFFFFFFFFFFFF0000L;
        
        // Version 7 in bits 48-51
        uuidV7MostSigBits |= 0x7000L;
        
        // Random bits in remaining 12 bits of mostSigBits
        uuidV7MostSigBits |= (mostSigBits & 0x0FFFL);
        
        // Variant (10) in bits 62-63 of leastSigBits
        long uuidV7LeastSigBits = (leastSigBits & 0x3FFFFFFFFFFFFFFFL) | 0x8000000000000000L;
        
        UUID uuidV7 = new UUID(uuidV7MostSigBits, uuidV7LeastSigBits);
        return uuidV7.toString();
    }

    /**
     * Calculate expiration time for a token
     */
    public Instant calculateWebExpiration() {
        return Instant.now().plusSeconds(magicLinkProperties.getWeb().getTtlSeconds());
    }

    /**
     * Calculate expiration time for an API token
     */
    public Instant calculateApiExpiration() {
        return Instant.now().plusSeconds(magicLinkProperties.getApi().getTtlSeconds());
    }
}
