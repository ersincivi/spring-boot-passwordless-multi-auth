package io.github.ersincivi.passwordless.service;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;

/**
 * T4.1: One-time authorization exchange codes for the mobile deep-link flow.
 *
 * The API magic-link verification endpoint (/api/auth/verify) runs in the
 * browser, so it cannot return JSON to the app. Instead it stores a one-time
 * exchange code here and redirects to the app scheme; the app then calls
 * POST /api/auth/exchange to trade the code for a token pair.
 *
 * Codes are short-lived (60 seconds) and single use.
 */
@Service
public class ExchangeCodeService {

    private static final String KEY_PREFIX = "passwordless:auth:exchange:";
    private static final Duration CODE_TTL = Duration.ofSeconds(60);
    private static final int CODE_BYTES = 32; // 256 bits of entropy

    private final RedisTemplate<String, Object> redisTemplate;
    private final SecureRandom secureRandom = new SecureRandom();

    public ExchangeCodeService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * Issue a one-time exchange code bound to the given username.
     */
    public String issue(String username) {
        byte[] bytes = new byte[CODE_BYTES];
        secureRandom.nextBytes(bytes);
        String code = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        redisTemplate.opsForValue().set(KEY_PREFIX + code, username, CODE_TTL);
        return code;
    }

    /**
     * Consume an exchange code: returns the bound username exactly once.
     * Subsequent calls with the same code (or expired/unknown codes) return empty.
     */
    public Optional<String> consume(String code) {
        String key = KEY_PREFIX + code;
        Object value = redisTemplate.opsForValue().get(key);
        if (value == null) {
            return Optional.empty();
        }
        redisTemplate.delete(key);
        return Optional.of(value.toString());
    }
}
