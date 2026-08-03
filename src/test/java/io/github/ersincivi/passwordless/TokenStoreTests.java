package io.github.ersincivi.passwordless;

import io.github.ersincivi.passwordless.security.TokenStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * T6.5: guards the T2.2/T2.3 token registry — access tokens are tracked by
 * userId + jti so that logout can revoke a single token before its natural
 * expiry.
 */
@ExtendWith(MockitoExtension.class)
class TokenStoreTests {

	private static final String USER_ID = "42";
	private static final String JTI = "7d2f1a9c-3b4e-4f5a-8c9d-0123456789ab";
	private static final String KEY = "passwordless:jwt:" + USER_ID + ":" + JTI;
	private static final Duration TTL = Duration.ofHours(1);

	@Mock
	private RedisTemplate<String, Object> redisTemplate;

	@Mock
	private ValueOperations<String, Object> valueOperations;

	private TokenStore tokenStore;

	@BeforeEach
	void setUp() {
		lenient().when(redisTemplate.opsForValue()).thenReturn(valueOperations);
		tokenStore = new TokenStore(redisTemplate);
	}

	@Test
	void storeJwtRegistersActiveMarkerWithTtl() {
		tokenStore.storeJwt(USER_ID, JTI, TTL);

		verify(valueOperations).set(KEY, "1", TTL);
	}

	@Test
	void isTokenActiveTrueWhenKeyExists() {
		when(redisTemplate.hasKey(KEY)).thenReturn(true);

		assertThat(tokenStore.isTokenActive(USER_ID, JTI)).isTrue();
	}

	@Test
	void isTokenActiveFalseWhenKeyMissing() {
		when(redisTemplate.hasKey(KEY)).thenReturn(false);

		assertThat(tokenStore.isTokenActive(USER_ID, JTI)).isFalse();
	}

	@Test
	void isTokenActiveFalseWhenHasKeyReturnsNull() {
		when(redisTemplate.hasKey(KEY)).thenReturn(null);

		assertThat(tokenStore.isTokenActive(USER_ID, JTI)).isFalse();
	}

	@Test
	void revokeDeletesTokenKey() {
		tokenStore.revoke(USER_ID, JTI);

		verify(redisTemplate).delete(KEY);
	}
}
