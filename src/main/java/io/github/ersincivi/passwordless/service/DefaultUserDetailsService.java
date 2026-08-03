package io.github.ersincivi.passwordless.service;

import io.github.ersincivi.passwordless.domain.CustomUserDetails;
import io.github.ersincivi.passwordless.domain.User;
import io.github.ersincivi.passwordless.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Service
public class DefaultUserDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	public DefaultUserDetailsService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepository.findByUsername(username)
			.orElseThrow(() -> new UsernameNotFoundException("User not found"));
		
		Set<GrantedAuthority> authorities = user.getRoles().stream()
			.flatMap(role -> {
				Set<GrantedAuthority> roleAuth = role.getAuthorities().stream()
					.map(a -> new SimpleGrantedAuthority(a.getName()))
					.collect(Collectors.toSet());
				roleAuth.add(new SimpleGrantedAuthority("ROLE_" + role.getCode().name()));
				return roleAuth.stream();
			})
			.collect(Collectors.toSet());
		
		// Return CustomUserDetails that exposes user's name and profileImage
		return new CustomUserDetails(user, authorities);
	}
}


