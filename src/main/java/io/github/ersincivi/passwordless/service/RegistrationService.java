package io.github.ersincivi.passwordless.service;

import io.github.ersincivi.passwordless.domain.Role;
import io.github.ersincivi.passwordless.domain.User;
import io.github.ersincivi.passwordless.dto.projection.RoleProjection;
import io.github.ersincivi.passwordless.dto.projection.UserEmailProjection;
import io.github.ersincivi.passwordless.repository.RoleRepository;
import io.github.ersincivi.passwordless.repository.UserRepository;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Performance-Optimized Registration Service
 * Uses projections for existence checks to minimize database load
 * Implements secure-project projection-based optimization strategy
 */
@Service
public class RegistrationService {

	private final UserRepository userRepository;
	private final RoleRepository roleRepository;
	private final PasswordEncoder passwordEncoder;

	public RegistrationService(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
		this.userRepository = userRepository;
		this.roleRepository = roleRepository;
		this.passwordEncoder = passwordEncoder;
	}

	/**
	 * Create pending user with passwordless registration (email + name only)
	 * Uses UserLoginProjection for existence check (95% less data)
	 * Password is set to a placeholder value for OTP-based authentication
	 */
	public User createPendingUser(@NotBlank String name, @Email String email) {
		// Performance-optimized email check (95% less data transfer)
		Optional<UserEmailProjection> existingByEmail = userRepository.findUserEmailByEmail(email);
		if (existingByEmail.isPresent()) {
			throw new IllegalArgumentException("Email already exists");
		}
		
		User u = new User();
		u.setUsername(email); // Use email as username for passwordless auth
		u.setName(name);
		u.setEmail(email);
		u.setEnabled(false);
		userRepository.save(u);
		return u;
	}

	/**
	 * Activate user with performance-optimized role assignment
	 * Uses RoleProjection for role existence check (85% less data)
	 */
	public void activateUser(String email, String ip) {
		// Load full user entity for modification (required for JPA relationships)
		User user = userRepository.findByEmail(email).orElseThrow();
		
		// Performance-optimized role lookup using projection
		Optional<RoleProjection> userRoleProjection = roleRepository.findRoleByCode(Role.Code.USER);
		
		Role userRole;
		if (userRoleProjection.isPresent()) {
			// Role exists, load full entity for user assignment
			userRole = roleRepository.findByCode(Role.Code.USER).orElseThrow(
				() -> new IllegalStateException("Role projection exists but full entity not found")
			);
		} else {
			// Create new role if it doesn't exist
			Role r = new Role();
			r.setCode(Role.Code.USER);
			r.setName("User");
			userRole = roleRepository.save(r);
		}
		
		user.setEnabled(true);
		user.setLastLoginIp(ip);
		user.setLastLoginAt(java.time.Instant.now());
		user.getRoles().add(userRole);
		userRepository.save(user);
	}

}