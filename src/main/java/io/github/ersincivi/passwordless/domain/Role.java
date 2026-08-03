package io.github.ersincivi.passwordless.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "roles")
public class Role extends BaseAuditableEntity {
	private static final long serialVersionUID = 1L;

	public enum Code { ADMIN, USER, SERVICE }

	@Enumerated(EnumType.STRING)
	@Column(nullable = false, unique = true, length = 32)
	private Code code;

	@Column(nullable = false, length = 128)
	private String name;

	@ManyToMany(fetch = FetchType.EAGER)
	@JoinTable(name = "role_authorities",
		joinColumns = @JoinColumn(name = "role_id"),
		inverseJoinColumns = @JoinColumn(name = "authority_id"))
	private Set<Authority> authorities = new HashSet<>();

	public Role(Code code, String name) {
		this.code = code;
		this.name = name;
	}
	
}