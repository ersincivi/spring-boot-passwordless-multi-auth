package io.github.ersincivi.passwordless.service;

import io.github.ersincivi.passwordless.domain.LastLoginInfo;
import io.github.ersincivi.passwordless.domain.User;
import io.github.ersincivi.passwordless.repository.LastLoginInfoRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Service to manage last login information for "Continue with this account" feature
 */
@Service
public class LastLoginInfoService {

    private static final Logger log = LoggerFactory.getLogger(LastLoginInfoService.class);

    private final LastLoginInfoRepository lastLoginInfoRepository;

    public LastLoginInfoService(LastLoginInfoRepository lastLoginInfoRepository) {
        this.lastLoginInfoRepository = lastLoginInfoRepository;
    }

    /**
     * Save or update last login information
     */
    @Transactional
    public void saveLastLoginInfo(User user, String loginMethod) {
        try {
            Optional<LastLoginInfo> existing = lastLoginInfoRepository.findByUserId(user.getId());

            LastLoginInfo loginInfo;
            if (existing.isPresent()) {
                // Update existing record
                loginInfo = existing.get();
                loginInfo.setLoginMethod(loginMethod);
                loginInfo.setUserName(user.getName());
                loginInfo.setProfileImageUrl(user.getProfileImage());
                loginInfo.setEmail(user.getEmail());
                loginInfo.setLastLoginAt(Instant.now());
            } else {
                // Create new record
                loginInfo = new LastLoginInfo(
                        user.getId(),
                        loginMethod,
                        user.getName(),
                        user.getProfileImage(),
                        user.getEmail()
                );
            }

            lastLoginInfoRepository.save(loginInfo);
            log.info("Saved last login info for user {} with method {}", user.getEmail(), loginMethod);

        } catch (Exception e) {
            log.error("Error saving last login info for user {}", user.getEmail(), e);
        }
    }

    /**
     * Get last login information by user ID
     */
    public Optional<LastLoginInfo> getLastLoginInfo(UUID userId) {
        return lastLoginInfoRepository.findByUserId(userId);
    }

    /**
     * Get last login information by email
     */
    public Optional<LastLoginInfo> getLastLoginInfoByEmail(String email) {
        return lastLoginInfoRepository.findByEmail(email);
    }

    /**
     * Delete last login information (e.g., on logout)
     */
    @Transactional
    public void deleteLastLoginInfo(UUID userId) {
        try {
            lastLoginInfoRepository.deleteByUserId(userId);
            log.info("Deleted last login info for user ID {}", userId);
        } catch (Exception e) {
            log.error("Error deleting last login info for user ID {}", userId, e);
        }
    }
}
