package io.github.ersincivi.passwordless.repository;

import io.github.ersincivi.passwordless.domain.User;
import io.github.ersincivi.passwordless.dto.projection.UserEmailProjection;
import io.github.ersincivi.passwordless.dto.projection.UserLoginProjection;
import io.github.ersincivi.passwordless.dto.projection.UserMfaProjection;
import io.github.ersincivi.passwordless.dto.projection.UserMfaSettingsProjection;
import io.github.ersincivi.passwordless.dto.projection.UserLastLoginProjection;
import io.github.ersincivi.passwordless.dto.projection.UserSecurityProjection;
import io.github.ersincivi.passwordless.dto.projection.UserSummaryProjection;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {

	Optional<User> findByUsername(String username);

	Optional<User> findByEmail(String email);
	
	// Find user by OAuth subject (app-scoped user ID from OAuth provider)
	Optional<User> findByOauthSubject(String oauthSubject);
	
	Optional<UserLoginProjection> findUserLoginByUsername(String username);
	
	Optional<UserEmailProjection> findUserEmailByEmail(String email);
	
	Optional<UserMfaProjection> findUserMfaByUsername(String username);

	Optional<UserMfaSettingsProjection> findUserMfaSettingsByUsername(String username);
	
	Optional<UserLastLoginProjection> findUserLastLoginByUsername(String username);

	Optional<UserLastLoginProjection> findUserLastLoginByEmail(String email);
	
	Optional<UserSecurityProjection> findUserSecurityByUsername(String username);
	
	List<UserSummaryProjection> findUserSummariesByEnabledTrue();

	List<UserSummaryProjection> findUserSummariesByEnabledFalse();

	List<UserSummaryProjection> findUserSummariesByLockedTrue();
	
	List<UserSummaryProjection> findUserSummariesByLastLoginAtBefore(Instant cutoffDate);
	
	List<UserSummaryProjection> findUserSummariesByOauthProviderIsNotNull();

	@Modifying
    @Query("update User u set u.phoneNumber = :phoneNumber where u.username = :username")
    int updatePhoneNumber(@Param("username") String username, @Param("phoneNumber") String phoneNumber);

	@Modifying
    @Query("update User u set u.lastLoginIp = :lastLoginIp where u.username = :username")
    int updateLastLoginIp(@Param("username") String username, @Param("lastLoginIp") String lastLoginIp);

	@Modifying
    @Query("update User u set u.mfaSecret = :mfaSecret, u.mfaEnabled = :mfaEnabled where u.username = :username")
    int updateMfaTotp(@Param("username") String username, @Param("mfaSecret") String mfaSecret, @Param("mfaEnabled") boolean mfaEnabled);

}