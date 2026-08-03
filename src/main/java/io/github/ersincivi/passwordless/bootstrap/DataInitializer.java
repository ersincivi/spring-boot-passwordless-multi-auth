package io.github.ersincivi.passwordless.bootstrap;

import io.github.ersincivi.passwordless.domain.Role;
import io.github.ersincivi.passwordless.domain.User;
import io.github.ersincivi.passwordless.dto.projection.RoleProjection;
import io.github.ersincivi.passwordless.dto.projection.UserLoginProjection;
import io.github.ersincivi.passwordless.repository.RoleRepository;
import io.github.ersincivi.passwordless.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Component
@Profile({"dev"}) // Development profile only
public class DataInitializer implements ApplicationRunner {

	private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

	private final RoleRepository roleRepository;
	private final UserRepository userRepository;
	
	public DataInitializer(RoleRepository roleRepository, UserRepository userRepository) {
		this.roleRepository = roleRepository;
		this.userRepository = userRepository;
	}

	@Override
	public void run(ApplicationArguments args) {
		// Admin User: username=admin, email=admin@example.com, role=ADMIN
		// Regular User: username=user, email=user@example.com, role=USER

		log.info("Setting up demo users (dev profile)...");

		Role adminRole = createOrGetRole(Role.Code.ADMIN, "Administrator");
		Role userRole = createOrGetRole(Role.Code.USER, "User");

		createOrGetUser("Administrator", "admin", "admin@example.com", adminRole, true);
		createOrGetUser("User", "user", "user@example.com", userRole, false);

		log.info("First-run setup complete. Demo accounts: admin@example.com (ADMIN) and "
				+ "user@example.com (USER) - no passwords, log in via magic link or OTP "
				+ "(mails land in Mailpit at http://localhost:8025).");
	}

	private Role createOrGetRole(Role.Code code, String name) {
		// First check with lightweight role projection
		Optional<RoleProjection> existingRole = roleRepository.findRoleByCode(code);
		
		if (existingRole.isPresent()) {
            // Role exists, create a new Role object with the projection data
			return new Role(existingRole.get().getCode(), existingRole.get().getName());
		} else {
			// Role doesn't exist, create new one
			Role role = new Role();
			role.setCode(code);
			role.setName(name);
			
			return roleRepository.save(role);
		}
	}
	
	private void createOrGetUser(String name, String username, String email, Role role, boolean isAdmin) {
		// First check with user projection
		Optional<UserLoginProjection> existingUser = userRepository.findUserLoginByUsername(username);

		if (existingUser.isEmpty()) {
			// User doesn't exist, create new one
			User user = new User();
            user.setName(name);
			user.setUsername(username);
			user.setEmail(email);
			user.setEnabled(true);
			user.setLastLoginIp("0:0:0:0:0:0:0:1");
			user.setLastLoginAt(java.time.Instant.now());
			
			// Assign role
			Set<Role> roles = new HashSet<>();
			roles.add(role);

			user.setRoles(roles);
			userRepository.save(user);
			log.info("Created {} user: username={}", isAdmin ? "ADMIN" : "USER", username);
		}
	}
}