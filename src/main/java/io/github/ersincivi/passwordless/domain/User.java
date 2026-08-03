package io.github.ersincivi.passwordless.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "users")
public class User extends BaseAuditableEntity {
	private static final long serialVersionUID = 1L;

	@Column(nullable = false, unique = true, length = 64)
	private String username;

	@Column(nullable = false, unique = true, length = 160)
	private String email;

	@Column(length = 100)
	private String name;

	@Column(length = 512)
	private String profileImage;

	@Column(length = 24)
	private String phoneNumber;

	@Column(nullable = false)
	private boolean enabled = false;

	@Column(nullable = false)
	private boolean locked = false;

	@Column(length = 45)
	private String lastLoginIp;

	@Column
	private Instant lastLoginAt;

	@Column(length = 128)
	private String mfaSecret; // for Google Authenticator

	@Column
	private Boolean mfaEnabled = false;

	// OAuth2/OpenID Connect linking
	@Column(length = 32)
	private String oauthProvider; // e.g., "google"

	@Column(length = 128)
	private String oauthSubject; // provider user id (sub)

	@ManyToMany(fetch = FetchType.EAGER)
	@JoinTable(name = "user_roles",
		joinColumns = @JoinColumn(name = "user_id"),
		inverseJoinColumns = @JoinColumn(name = "role_id"))
	private Set<Role> roles = new HashSet<>();
}