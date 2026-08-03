package io.github.ersincivi.passwordless.listener;

import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class SecurityEventListeners implements HttpSessionListener {

	private static final Logger log = LoggerFactory.getLogger(SecurityEventListeners.class);

	@EventListener
	public void onAuthSuccess(AuthenticationSuccessEvent event) {
		Authentication auth = event.getAuthentication();
		String username = principalName(auth);
		log.info("Login successful. username={}", username);
	}

	@EventListener
	public void onAuthFailure(AbstractAuthenticationFailureEvent event) {
		Authentication auth = event.getAuthentication();
		String username = principalName(auth);
		log.warn("Login failed! type={} username={}", event.getClass().getSimpleName(), username);
	}

	@Override
	public void sessionCreated(HttpSessionEvent se) {
		log.debug("Session created. id={}", se.getSession().getId());
	}

	@Override
	public void sessionDestroyed(HttpSessionEvent se) {
		log.debug("Session destroyed. id={}", se.getSession().getId());
	}

	private String principalName(Authentication auth) {
		if (auth == null) {
			return "anonymous";
		}
		Object p = auth.getPrincipal();
		if (p instanceof UserDetails ud) {
			return ud.getUsername();
		}
		return String.valueOf(p);
	}
}


