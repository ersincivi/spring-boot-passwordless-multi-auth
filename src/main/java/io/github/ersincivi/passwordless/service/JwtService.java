package io.github.ersincivi.passwordless.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

@Service
public class JwtService {

    /**
     * No default value: the application must fail fast at startup if the secret
     * is not configured (see application.yml / JWT_SECRET environment variable).
     */
    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.ttl-seconds:3600}")
    private long ttlSeconds;

    private SecretKey secretKey;

    @PostConstruct
    void init() {
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        // HS256 requires a key of at least 256 bits (32 bytes)
        if (keyBytes.length < 32) {
            throw new IllegalStateException(
                    "app.jwt.secret must be at least 256 bits (32 bytes) for HS256. " +
                    "Set a strong secret via the JWT_SECRET environment variable.");
        }
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Issue a new access token with a unique jti (used for revocation via TokenStore).
     */
    public IssuedToken issueToken(String subject, Map<String, Object> claims) {
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(ttlSeconds);
        String jti = UUID.randomUUID().toString();

        String token = Jwts.builder()
            .claims(claims)
            .subject(subject)
            .id(jti)
            .issuedAt(Date.from(now))
            .expiration(Date.from(expiresAt))
            .signWith(secretKey)
            .compact();

        return new IssuedToken(token, jti, expiresAt);
    }

    /**
     * Parse and validate a token signature and expiration.
     * Throws io.jsonwebtoken.JwtException (incl. ExpiredJwtException) when invalid.
     */
    public Jws<Claims> parseToken(String token) {
        return Jwts.parser()
            .verifyWith(secretKey)
            .build()
            .parseSignedClaims(token);
    }

    public long getTtlSeconds() {
        return ttlSeconds;
    }

    /**
     * A freshly issued access token together with its unique id and expiration.
     */
    public record IssuedToken(String token, String jti, Instant expiresAt) {
    }
}
