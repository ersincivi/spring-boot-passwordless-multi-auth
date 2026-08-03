package io.github.ersincivi.passwordless;

import io.github.ersincivi.passwordless.service.RefreshTokenService;
import io.github.ersincivi.passwordless.service.RefreshTokenService.IssuedRefreshToken;
import io.github.ersincivi.passwordless.service.RefreshTokenService.RotationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.SetOperations;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * T6.5: guards the T2.4 refresh-token flow — opaque tokens in Redis, single-use
 * rotation (presenting a token invalidates it and issues a new one) and
 * revocation both per token and per user.
 */
@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTests {

	private static final String USERNAME = "user@example.com";
	private static final long TTL_SECONDS = 2_592_000L; // 30 days
	private static final String USER_KEY = "passwordless:refresh:user:" + USERNAME;

	@Mock
	private RedisTemplate<String, Object> redisTemplate;

	@Mock
	private ValueOperations<String, Object> valueOperations;

	@Mock
	private SetOperations<String, Object> setOperations;

	private RefreshTokenService refreshTokenService;

	@BeforeEach
	void setUp() {
		lenient().when(redisTemplate.opsForValue()).thenReturn(valueOperations);
		lenient().when(redisTemplate.opsForSet()).thenReturn(setOperations);
		refreshTokenService = new RefreshTokenService(redisTemplate);
		ReflectionTestUtils.setField(refreshTokenService, "refreshTtlSeconds", TTL_SECONDS);
	}

	@Test
	void issueStoresTokenWithTtlAndTracksItInUserSet() {
		IssuedRefreshToken issued = refreshTokenService.issue(USERNAME);

		// 48 random bytes -> 64 base64url characters without padding
		assertThat(issued.token()).hasSize(64);
		assertThat(issued.expiresAt())
				.isAfter(Instant.now().plusSeconds(TTL_SECONDS - 60))
				.isBefore(Instant.now().plusSeconds(TTL_SECONDS + 60));

		verify(valueOperations).set("passwordless:refresh:token:" + issued.token(), USERNAME,
				Duration.ofSeconds(TTL_SECONDS));
		verify(setOperations).add(USER_KEY, issued.token());
		verify(redisTemplate).expire(USER_KEY, Duration.ofSeconds(TTL_SECONDS));
	}

	@Test
	void rotateInvalidatesPresentedTokenAndIssuesNewOne() {
		String oldToken = "old-token";
		when(valueOperations.get("passwordless:refresh:token:old-token")).thenReturn(USERNAME);

		Optional<RotationResult> result = refreshTokenService.rotate(oldToken);

		assertThat(result).isPresent();
		assertThat(result.get().username()).isEqualTo(USERNAME);
		assertThat(result.get().refreshToken().token()).isNotEqualTo(oldToken);

		// Single use: the presented token is invalidated immediately
		verify(redisTemplate).delete("passwordless:refresh:token:old-token");
		verify(setOperations).remove(USER_KEY, oldToken);
		// ...and a fresh token is stored for the same user
		verify(valueOperations).set(eq("passwordless:refresh:token:" + result.get().refreshToken().token()),
				eq(USERNAME), any(Duration.class));
	}

	@Test
	void rotateReturnsEmptyForUnknownToken() {
		when(valueOperations.get("passwordless:refresh:token:unknown")).thenReturn(null);

		Optional<RotationResult> result = refreshTokenService.rotate("unknown");

		assertThat(result).isEmpty();
		verify(redisTemplate, never()).delete(any(String.class));
		verify(setOperations, never()).remove(any(), any());
	}

	@Test
	void revokeRemovesTokenFromUserSetAndDeletesKey() {
		when(valueOperations.get("passwordless:refresh:token:tok")).thenReturn(USERNAME);

		refreshTokenService.revoke("tok");

		verify(setOperations).remove(USER_KEY, "tok");
		verify(redisTemplate).delete("passwordless:refresh:token:tok");
	}

	@Test
	void revokeDeletesKeyEvenWhenTokenUnknown() {
		when(valueOperations.get("passwordless:refresh:token:tok")).thenReturn(null);

		refreshTokenService.revoke("tok");

		verify(setOperations, never()).remove(any(), any());
		verify(redisTemplate).delete("passwordless:refresh:token:tok");
	}

	@Test
	void revokeAllForUserDeletesEveryTokenAndTheUserSet() {
		when(setOperations.members(USER_KEY)).thenReturn(Set.<Object>of("t1", "t2"));

		refreshTokenService.revokeAllForUser(USERNAME);

		verify(redisTemplate).delete("passwordless:refresh:token:t1");
		verify(redisTemplate).delete("passwordless:refresh:token:t2");
		verify(redisTemplate).delete(USER_KEY);
	}
}
