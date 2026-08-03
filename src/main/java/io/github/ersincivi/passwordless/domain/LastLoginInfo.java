package io.github.ersincivi.passwordless.domain;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

/**
 * Entity to track the last login method and user details for "Continue with this account" feature
 */
@Entity
@Table(name = "last_login_info")
public class LastLoginInfo {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private UUID userId;

    @Column(nullable = false, length = 50)
    private String loginMethod; // "email", "google", "github"

    @Column(length = 100)
    private String userName;

    @Column(length = 512)
    private String profileImageUrl;

    @Column(nullable = false)
    private Instant lastLoginAt;

    @Column(length = 255)
    private String email;

    // Constructors
    public LastLoginInfo() {
    }

    public LastLoginInfo(UUID userId, String loginMethod, String userName, String profileImageUrl, String email) {
        this.userId = userId;
        this.loginMethod = loginMethod;
        this.userName = userName;
        this.profileImageUrl = profileImageUrl;
        this.email = email;
        this.lastLoginAt = Instant.now();
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public UUID getUserId() {
        return userId;
    }

    public void setUserId(UUID userId) {
        this.userId = userId;
    }

    public String getLoginMethod() {
        return loginMethod;
    }

    public void setLoginMethod(String loginMethod) {
        this.loginMethod = loginMethod;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getProfileImageUrl() {
        return profileImageUrl;
    }

    public void setProfileImageUrl(String profileImageUrl) {
        this.profileImageUrl = profileImageUrl;
    }

    public Instant getLastLoginAt() {
        return lastLoginAt;
    }

    public void setLastLoginAt(Instant lastLoginAt) {
        this.lastLoginAt = lastLoginAt;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    @Override
    public String toString() {
        return "LastLoginInfo{" +
                "id=" + id +
                ", userId=" + userId +
                ", loginMethod='" + loginMethod + '\'' +
                ", userName='" + userName + '\'' +
                ", email='" + email + '\'' +
                ", lastLoginAt=" + lastLoginAt +
                '}';
    }
}
