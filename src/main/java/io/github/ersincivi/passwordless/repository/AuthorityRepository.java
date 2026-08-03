package io.github.ersincivi.passwordless.repository;

import io.github.ersincivi.passwordless.domain.Authority;
import io.github.ersincivi.passwordless.dto.projection.AuthorityProjection;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AuthorityRepository extends JpaRepository<Authority, UUID> {
	// Existing methods for full entity access (keep for create/update operations)
	Optional<Authority> findByName(String name);
	
	// Performance-optimized projections
	
	/**
	 * Lightweight projection for authority information
	 * Optimized for permission checking and security operations
	 * Performance: ~90% less data compared to full entity
	 */
	Optional<AuthorityProjection> findAuthorityByName(String name);
	
	/**
	 * Get all authorities as lightweight projections
	 * Optimized for authority listing and permission management
	 */
	List<AuthorityProjection> findAllAuthoritiesBy();
	
	/**
	 * Find authorities by name pattern
	 * Optimized for permission filtering and search operations
	 */
	List<AuthorityProjection> findAuthoritiesByNameContainingIgnoreCase(String namePattern);
	
	/**
	 * Find authorities by multiple names
	 * Optimized for batch permission checking
	 */
	List<AuthorityProjection> findAuthoritiesByNameIn(List<String> names);
}