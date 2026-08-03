package io.github.ersincivi.passwordless.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Service
public class RecaptchaService {

	@Value("${app.recaptcha.enabled:false}")
	private boolean enabled;

	@Value("${app.recaptcha.secret:}")
	private String secret;

	private final RestTemplate restTemplate = new RestTemplate();

	public boolean verify(String token, String remoteIp) {
		if (!enabled) return true;
		MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
		form.add("secret", secret);
		form.add("response", token);
		if (remoteIp != null) form.add("remoteip", remoteIp);
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		try {
			RecaptchaResponse resp = restTemplate.postForObject(
				"https://www.google.com/recaptcha/api/siteverify",
				new HttpEntity<>(form, headers),
				RecaptchaResponse.class
			);
			return resp != null && resp.success;
		} catch (Exception e) {
			return false;
		}
	}

	private static class RecaptchaResponse {
		public boolean success;
	}
}


