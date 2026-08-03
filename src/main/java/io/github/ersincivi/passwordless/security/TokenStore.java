package io.github.ersincivi.passwordless.security;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Redis-backed registry of active JWT access tokens.
 *
 * Tokens are stored by their unique jti claim, which allows:
 * - explicit revocation (logout)
 * - rejection of tokens that were issued before a credential change
 *
 * Keys have the form: passwordless:jwt:{userId}:{jti}
 */
@Component
public class TokenStore {

	private static final String KEY_PREFIX = "passwordless:jwt:";
	private static final String ACTIVE_VALUE = "1";

	private final RedisTemplate<String, Object> redisTemplate;

	public TokenStore(RedisTemplate<String, Object> redisTemplate) {
		this.redisTemplate = redisTemplate;
	}

	/**
	 * Register an access token as active for the given user.
	 */
	public void storeJwt(String userId, String jti, Duration ttl) {
		redisTemplate.opsForValue().set(key(userId, jti), ACTIVE_VALUE, ttl);
	}

	/**
	 * Check whether the given token id is still active (not revoked / not expired).
	 */
	public boolean isTokenActive(String userId, String jti) {
		return Boolean.TRUE.equals(redisTemplate.hasKey(key(userId, jti)));
	}

	/**
	 * Revoke a single access token (e.g. on logout).
	 */
	public void revoke(String userId, String jti) {
		redisTemplate.delete(key(userId, jti));
	}

	private String key(String userId, String jti) {
		return KEY_PREFIX + userId + ":" + jti;
	}
}
