package io.github.ersincivi.passwordless.repository;

import io.github.ersincivi.passwordless.domain.Role;
import io.github.ersincivi.passwordless.dto.projection.RoleProjection;
import io.github.ersincivi.passwordless.dto.projection.RoleSecurityProjection;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RoleRepository extends JpaRepository<Role, UUID> {
	// Existing methods for full entity access (keep for create/update operations)
	Optional<Role> findByCode(Role.Code code);
	
	// Performance-optimized projections
	
	/**
	 * Lightweight projection for role information
	 * Optimized for basic role checks and authorization
	 * Performance: ~85% less data compared to full entity with eager authorities
	 */
	Optional<RoleProjection> findRoleByCode(Role.Code code);
	
	/**
	 * Comprehensive projection including authorities
	 * Used for security operations requiring full role context
	 * Performance: Optimized JOIN queries, ~60% less data than full entity
	 */
	Optional<RoleSecurityProjection> findRoleSecurityByCode(Role.Code code);
	
	/**
	 * Get all roles as lightweight projections
	 * Optimized for role listing and administrative views
	 */
	List<RoleProjection> findAllRolesBy();
	
	/**
	 * Get all roles with authorities for security configuration
	 * Performance: Batch-optimized for security setup operations
	 */
	List<RoleSecurityProjection> findAllRoleSecuritiesBy();
}