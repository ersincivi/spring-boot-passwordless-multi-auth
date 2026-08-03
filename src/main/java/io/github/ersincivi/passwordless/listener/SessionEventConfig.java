package io.github.ersincivi.passwordless.listener;

import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SessionEventConfig {

	@Bean
	public ServletListenerRegistrationBean<SecurityEventListeners> sessionListenerRegistration(SecurityEventListeners listeners) {
		ServletListenerRegistrationBean<SecurityEventListeners> bean = new ServletListenerRegistrationBean<>();
		bean.setListener(listeners);
		bean.setOrder(1);
		return bean;
	}
}


