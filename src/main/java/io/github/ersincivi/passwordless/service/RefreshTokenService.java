package io.github.ersincivi.passwordless.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;

/**
 * Manages opaque, rotating refresh tokens stored in Redis.
 *
 * Properties:
 * - Single use: presenting a refresh token invalidates it and issues a new one (rotation).
 * - Reuse detection: a rotated-out token can no longer be used, limiting replay damage.
 * - Revocation: tokens can be revoked individually (logout) or per user (logout everywhere).
 *
 * Redis layout:
 * - passwordless:refresh:token:{token} -> username (TTL = refresh token lifetime)
 * - passwordless:refresh:user:{username} -> Set of active tokens for the user
 */
@Service
public class RefreshTokenService {

    private static final String TOKEN_KEY_PREFIX = "passwordless:refresh:token:";
    private static final String USER_KEY_PREFIX = "passwordless:refresh:user:";
    private static final int TOKEN_BYTES = 48; // 384 bits of entropy

    private final RedisTemplate<String, Object> redisTemplate;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${app.jwt.refresh-ttl-seconds:2592000}")
    private long refreshTtlSeconds;

    public RefreshTokenService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * Issue a new refresh token for the given user.
     */
    public IssuedRefreshToken issue(String username) {
        String token = generateToken();
        Duration ttl = Duration.ofSeconds(refreshTtlSeconds);

        redisTemplate.opsForValue().set(tokenKey(token), username, ttl);
        redisTemplate.opsForSet().add(userKey(username), token);
        redisTemplate.expire(userKey(username), ttl);

        return new IssuedRefreshToken(token, Instant.now().plusSeconds(refreshTtlSeconds));
    }

    /**
     * Rotate a refresh token: validate, invalidate the presented token and issue a new one.
     * Returns empty if the presented token is unknown (expired, revoked or already used).
     */
    public Optional<RotationResult> rotate(String presentedToken) {
        String tokenKey = tokenKey(presentedToken);
        Object value = redisTemplate.opsForValue().get(tokenKey);
        if (value == null) {
            return Optional.empty();
        }

        String username = value.toString();

        // Single use: the presented token is invalidated immediately
        redisTemplate.delete(tokenKey);
        redisTemplate.opsForSet().remove(userKey(username), presentedToken);

        IssuedRefreshToken newToken = issue(username);
        return Optional.of(new RotationResult(username, newToken));
    }

    /**
     * Revoke a single refresh token (e.g. on logout).
     */
    public void revoke(String token) {
        Object value = redisTemplate.opsForValue().get(tokenKey(token));
        if (value != null) {
            redisTemplate.opsForSet().remove(userKey(value.toString()), token);
        }
        redisTemplate.delete(tokenKey(token));
    }

    /**
     * Revoke all refresh tokens of a user (e.g. "logout from all devices").
     */
    public void revokeAllForUser(String username) {
        String userKey = userKey(username);
        Set<Object> tokens = redisTemplate.opsForSet().members(userKey);
        if (tokens != null) {
            for (Object token : tokens) {
                redisTemplate.delete(tokenKey(token.toString()));
            }
        }
        redisTemplate.delete(userKey);
    }

    public long getRefreshTtlSeconds() {
        return refreshTtlSeconds;
    }

    private String generateToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String tokenKey(String token) {
        return TOKEN_KEY_PREFIX + token;
    }

    private String userKey(String username) {
        return USER_KEY_PREFIX + username;
    }

    public record IssuedRefreshToken(String token, Instant expiresAt) {
    }

    public record RotationResult(String username, IssuedRefreshToken refreshToken) {
    }
}
