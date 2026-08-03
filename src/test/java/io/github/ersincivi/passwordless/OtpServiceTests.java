package io.github.ersincivi.passwordless;

import io.github.ersincivi.passwordless.service.OTPService;
import io.github.ersincivi.passwordless.service.OTPService.Purpose;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * T6.5: guards the T3.2 OTP hardening — per-purpose namespaces, single-use
 * codes and the per-code attempt limit that invalidates a code once
 * MAX_VERIFY_ATTEMPTS (5) wrong verifications have been presented.
 */
@ExtendWith(MockitoExtension.class)
class OtpServiceTests {

	private static final String EMAIL = "user@example.com";
	private static final String LOGIN_KEY = "passwordless:otp:login:" + EMAIL;
	private static final String LOGIN_ATTEMPTS_KEY = "passwordless:otp:attempts:login:" + EMAIL;
	private static final Duration OTP_TTL = Duration.ofMinutes(15);

	@Mock
	private RedisTemplate<String, Object> redisTemplate;

	@Mock
	private ValueOperations<String, Object> valueOperations;

	private OTPService otpService;

	@BeforeEach
	void setUp() {
		lenient().when(redisTemplate.opsForValue()).thenReturn(valueOperations);
		otpService = new OTPService(redisTemplate);
	}

	@Test
	void generateOtpStoresSixDigitCodeWithTtlAndResetsAttemptCounter() {
		String otp = otpService.generateOtp(Purpose.LOGIN, EMAIL);

		assertThat(otp).matches("\\d{6}");

		ArgumentCaptor<String> codeCaptor = ArgumentCaptor.forClass(String.class);
		verify(valueOperations).set(eq(LOGIN_KEY), codeCaptor.capture(), eq(OTP_TTL));
		assertThat(codeCaptor.getValue()).isEqualTo(otp);
		verify(redisTemplate).delete(LOGIN_ATTEMPTS_KEY);
	}

	@Test
	void generateOtpUsesSeparateNamespacePerPurpose() {
		otpService.generateOtp(Purpose.LOGIN, EMAIL);
		otpService.generateOtp(Purpose.REGISTER, EMAIL);

		verify(valueOperations).set(eq("passwordless:otp:login:" + EMAIL), any(), eq(OTP_TTL));
		verify(valueOperations).set(eq("passwordless:otp:register:" + EMAIL), any(), eq(OTP_TTL));
	}

	@Test
	void verifyOtpSucceedsAndConsumesCodeAndCounter() {
		when(valueOperations.get(LOGIN_KEY)).thenReturn("123456");

		assertThat(otpService.verifyOtp(Purpose.LOGIN, EMAIL, "123456")).isTrue();

		verify(redisTemplate).delete(LOGIN_KEY);
		verify(redisTemplate).delete(LOGIN_ATTEMPTS_KEY);
	}

	@Test
	void verifyOtpFailsWhenCodeIsMissing() {
		when(valueOperations.get(LOGIN_KEY)).thenReturn(null);

		assertThat(otpService.verifyOtp(Purpose.LOGIN, EMAIL, "123456")).isFalse();

		verify(valueOperations, never()).increment(any());
		verify(redisTemplate, never()).delete(any(String.class));
	}

	@Test
	void verifyOtpWrongCodeCountsAttemptButKeepsCodeBelowLimit() {
		when(valueOperations.get(LOGIN_KEY)).thenReturn("123456");
		when(valueOperations.increment(LOGIN_ATTEMPTS_KEY)).thenReturn(1L);

		assertThat(otpService.verifyOtp(Purpose.LOGIN, EMAIL, "000000")).isFalse();

		verify(redisTemplate).expire(LOGIN_ATTEMPTS_KEY, OTP_TTL);
		verify(redisTemplate, never()).delete(LOGIN_KEY);
		verify(redisTemplate, never()).delete(LOGIN_ATTEMPTS_KEY);
	}

	@Test
	void verifyOtpDeletesCodeAndCounterWhenAttemptLimitExhausted() {
		when(valueOperations.get(LOGIN_KEY)).thenReturn("123456");
		when(valueOperations.increment(LOGIN_ATTEMPTS_KEY)).thenReturn(5L);

		assertThat(otpService.verifyOtp(Purpose.LOGIN, EMAIL, "000000")).isFalse();

		verify(redisTemplate).delete(LOGIN_KEY);
		verify(redisTemplate).delete(LOGIN_ATTEMPTS_KEY);
	}

	@Test
	void verifyOtpTreatsNullOtpAsFailedAttempt() {
		when(valueOperations.get(LOGIN_KEY)).thenReturn("123456");
		when(valueOperations.increment(LOGIN_ATTEMPTS_KEY)).thenReturn(1L);

		assertThat(otpService.verifyOtp(Purpose.LOGIN, EMAIL, null)).isFalse();
	}
}
