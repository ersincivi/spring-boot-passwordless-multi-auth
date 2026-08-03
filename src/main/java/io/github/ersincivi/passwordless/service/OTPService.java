package io.github.ersincivi.passwordless.service;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;

/**
 * T3.2: Hardened one-time-password service.
 *
 * - Separate Redis namespaces per purpose (login / register / geo) so a code
 *   issued for one flow cannot be replayed in another flow.
 * - Per-code verification attempt limit: the code is deleted when the limit
 *   is exhausted, forcing a fresh code request instead of allowing brute force.
 * - Codes are single use: a successful verification deletes the code.
 */
@Service
public class OTPService {

	public enum Purpose {
		LOGIN, REGISTER, GEO
	}

	private static final Duration OTP_TTL = Duration.ofMinutes(15);
	private static final int MAX_VERIFY_ATTEMPTS = 5;

	private final RedisTemplate<String, Object> redisTemplate;
	private final SecureRandom secureRandom = new SecureRandom();

	public OTPService(RedisTemplate<String, Object> redisTemplate) {
		this.redisTemplate = redisTemplate;
	}

	public String generateOtp(Purpose purpose, String key) {
		String otp = String.format("%06d", secureRandom.nextInt(1_000_000));
		redisTemplate.opsForValue().set(otpKey(purpose, key), otp, OTP_TTL);
		// New code -> reset the attempt counter
		redisTemplate.delete(attemptsKey(purpose, key));
		return otp;
	}

	/**
	 * Verify a code for the given purpose. A failed attempt increments the
	 * per-code attempt counter; once MAX_VERIFY_ATTEMPTS is reached the code
	 * is invalidated and a new one must be requested.
	 */
	public boolean verifyOtp(Purpose purpose, String key, String otp) {
		String redisKey = otpKey(purpose, key);
		Object val = redisTemplate.opsForValue().get(redisKey);

		if (val == null) {
			return false;
		}

		String storedOtp = val.toString().trim();
		String userOtp = otp != null ? otp.trim() : "";

		if (storedOtp.equals(userOtp)) {
			redisTemplate.delete(redisKey);
			redisTemplate.delete(attemptsKey(purpose, key));
			return true;
		}

		// Failed attempt: count it and invalidate the code on exhaustion
		String attemptsKey = attemptsKey(purpose, key);
		Long attempts = redisTemplate.opsForValue().increment(attemptsKey);
		redisTemplate.expire(attemptsKey, OTP_TTL);
		if (attempts != null && attempts >= MAX_VERIFY_ATTEMPTS) {
			redisTemplate.delete(redisKey);
			redisTemplate.delete(attemptsKey);
		}
		return false;
	}

	private String otpKey(Purpose purpose, String key) {
		return "passwordless:otp:" + purpose.name().toLowerCase() + ":" + key;
	}

	private String attemptsKey(Purpose purpose, String key) {
		return "passwordless:otp:attempts:" + purpose.name().toLowerCase() + ":" + key;
	}
}
