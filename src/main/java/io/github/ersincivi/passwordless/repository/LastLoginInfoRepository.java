package io.github.ersincivi.passwordless.repository;

import io.github.ersincivi.passwordless.domain.LastLoginInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface LastLoginInfoRepository extends JpaRepository<LastLoginInfo, Long> {

    /**
     * Find last login info by user ID
     */
    Optional<LastLoginInfo> findByUserId(UUID userId);

    /**
     * Find last login info by email
     */
    Optional<LastLoginInfo> findByEmail(String email);

    /**
     * Delete last login info by user ID
     */
    void deleteByUserId(UUID userId);
}
