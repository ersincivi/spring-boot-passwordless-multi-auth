package io.github.ersincivi.passwordless.service;

import io.github.ersincivi.passwordless.domain.CustomUserDetails;
import io.github.ersincivi.passwordless.domain.Role;
import io.github.ersincivi.passwordless.domain.User;
import io.github.ersincivi.passwordless.repository.RoleRepository;
import io.github.ersincivi.passwordless.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Service
public class CustomOidcUserService extends OidcUserService {

	private static final Logger log = LoggerFactory.getLogger(CustomOidcUserService.class);

	private final UserRepository userRepository;
	private final RoleRepository roleRepository;

	public CustomOidcUserService(UserRepository userRepository, RoleRepository roleRepository) {
		this.userRepository = userRepository;
		this.roleRepository = roleRepository;
	}

	@Override
	@Transactional
	public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
		OidcUser oidcUser = super.loadUser(userRequest);
		String registrationId = userRequest.getClientRegistration().getRegistrationId();
		Map<String, Object> attributes = oidcUser.getAttributes();

		log.info("===== CustomOidcUserService DEBUG =====");
		log.info("RegistrationId: {}", registrationId);
		log.info("Attributes: {}", attributes);

		// Prepare mutable claim variables
		String subVal = asString(attributes.get("sub"));
		if (subVal == null || subVal.isEmpty()) {
			// Fallback to provider-specific id if sub missing
			subVal = asString(attributes.get("id"));
		}

		// Email: try attributes, then id token claims, then user info claims
		String emailVal = asString(attributes.get("email"));
		if (emailVal == null || emailVal.isEmpty()) {
			emailVal = asString(oidcUser.getIdToken() != null ? oidcUser.getIdToken().getClaims().get("email") : null);
		}
		if ((emailVal == null || emailVal.isEmpty()) && oidcUser.getUserInfo() != null) {
			emailVal = asString(oidcUser.getUserInfo().getClaims().get("email"));
		}

		// Name: try attributes, then compose given_name + family_name, then user info
		String nameVal = asString(attributes.get("name"));
		if (nameVal == null || nameVal.isEmpty()) {
			String given = asString(attributes.get("given_name"));
			String family = asString(attributes.get("family_name"));
			if (given != null || family != null) {
				nameVal = ((given != null ? given : "") + " " + (family != null ? family : "")).trim();
			}
		}
		if ((nameVal == null || nameVal.isEmpty()) && oidcUser.getUserInfo() != null) {
			nameVal = asString(oidcUser.getUserInfo().getClaims().get("name"));
		}

		// Profile Image: try picture claim from attributes
		String profileImageVal = asString(attributes.get("picture"));
		if ((profileImageVal == null || profileImageVal.isEmpty()) && oidcUser.getIdToken() != null) {
			profileImageVal = asString(oidcUser.getIdToken().getClaims().get("picture"));
		}
		if ((profileImageVal == null || profileImageVal.isEmpty()) && oidcUser.getUserInfo() != null) {
			profileImageVal = asString(oidcUser.getUserInfo().getClaims().get("picture"));
		}

		// Check required claims
		if (emailVal == null || emailVal.isEmpty() || subVal == null || subVal.isEmpty()) {
			throw new OAuth2AuthenticationException("Missing required claims from OIDC provider");
		}

		final String subject = subVal;
		final String email = emailVal;
		final String name = nameVal;
		final String profileImage = profileImageVal;

		log.info("OIDC name: {}", name);
		log.info("OIDC user: {}", email);
		log.info("OIDC provider: {}", registrationId);
		log.info("OIDC subject: {}", subject);

		// Find or create user
		User user = userRepository.findByEmail(email).orElse(null);
		final boolean isNewUser = (user == null);
		if (isNewUser) {
			log.info("Creating new OIDC user: {}", email);
			user = new User();
			user.setEmail(email);
			user.setEnabled(true);
			// Initialize roles collection
			user.setRoles(new HashSet<>());
			// Initialize MFA settings
			user.setMfaEnabled(false);
		} else {
			log.info("Found existing OIDC user: {}", email);
		}

		// Update OAuth provider info
        user.setUsername(email);
        user.setName(name != null && !name.isEmpty() ? name : null);
        user.setProfileImage(profileImage != null && !profileImage.isEmpty() ? profileImage : null);
		user.setOauthProvider(registrationId.toLowerCase());
		user.setOauthSubject(subject);

		// Update login tracking
		String clientIp = getClientIpAddress();
		user.setLastLoginIp(clientIp);
		user.setLastLoginAt(Instant.now());
		log.info("Updated login tracking - IP: {}, Time: {}", clientIp, user.getLastLoginAt());

		// Ensure user has USER role
		if (user.getRoles() == null || user.getRoles().isEmpty()) {
			if (user.getRoles() == null) {
				user.setRoles(new HashSet<>());
			}
			final User finalUser = user;
			roleRepository.findByCode(Role.Code.USER).ifPresent(r -> {
				finalUser.getRoles().add(r);
				log.info("Added USER role to OIDC user: {}", email);
			});
		}

		try {
			user = userRepository.save(user);
			log.info("Successfully saved OIDC user: {} with ID: {}", user.getUsername(), user.getId());
		} catch (Exception e) {
			log.error("Error saving OIDC user: {}", email, e);
			throw new OAuth2AuthenticationException("Failed to save user: " + e.getMessage());
		}

		log.info("===== CustomOidcUserService END =====");

		// Build authorities from roles (both role authorities and ROLE_ prefix)
		Set<GrantedAuthority> authorities = new HashSet<>();
		user.getRoles().forEach(role -> {
			// Add role-specific authorities
			role.getAuthorities().forEach(authority -> 
				authorities.add(new SimpleGrantedAuthority(authority.getName()))
			);
			// Add ROLE_ prefix for role-based checks
			authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getCode().name()));
		});

		// Return UNIFIED CustomUserDetails (implements OidcUser)
		// This ensures consistent principal type across all authentication methods
		return new CustomUserDetails(user, authorities, oidcUser.getAttributes(), 
									 oidcUser.getIdToken(), oidcUser.getUserInfo());
	}

	private String asString(Object value) {
		return value == null ? null : String.valueOf(value);
	}

	private String getClientIpAddress() {
		try {
			ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder
					.getRequestAttributes();
			if (attributes != null) {
				HttpServletRequest request = attributes.getRequest();
				return request.getRemoteAddr();
			}
		} catch (Exception e) {
			log.warn("Failed to get client IP address: {}", e.getMessage());
		}
		return "unknown";
	}
}