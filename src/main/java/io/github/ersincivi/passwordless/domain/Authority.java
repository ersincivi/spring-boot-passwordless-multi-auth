package io.github.ersincivi.passwordless.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "authorities")
public class Authority extends BaseAuditableEntity {
	private static final long serialVersionUID = 1L;

	@Column(nullable = false, unique = true, length = 64)
	private String name; // e.g., READ_USERS, WRITE_USERS
}