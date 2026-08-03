package io.github.ersincivi.passwordless.service;

import io.github.ersincivi.passwordless.domain.CustomUserDetails;
import io.github.ersincivi.passwordless.domain.Role;
import io.github.ersincivi.passwordless.domain.User;
import io.github.ersincivi.passwordless.dto.GitHubEmail;
import io.github.ersincivi.passwordless.repository.RoleRepository;
import io.github.ersincivi.passwordless.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestClient;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;

import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Service
public class OAuth2UserService extends DefaultOAuth2UserService {

    private static final Logger log = LoggerFactory.getLogger(OAuth2UserService.class);

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final LastLoginInfoService lastLoginInfoService;
    // private final WebClient webClient;
    private final RestClient restClient;

    public OAuth2UserService(UserRepository userRepository, RoleRepository roleRepository,
            LastLoginInfoService lastLoginInfoService, RestClient restClient) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.lastLoginInfoService = lastLoginInfoService;
        this.restClient = restClient;
    }

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User delegate = super.loadUser(userRequest);
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        Map<String, Object> attributes = delegate.getAttributes();

        log.info("===== OAuth2UserService DEBUG =====");
        log.info("Registration ID: {}", registrationId);
        log.info("Attributes: {}", attributes);

        String subject;
        String email;
        String name;
        String username = null;
        String profileImage;

        if ("google".equalsIgnoreCase(registrationId)) {
            // OpenID Connect standard claims for Google
            subject = asString(attributes.get("sub"));
            email = asString(attributes.get("email"));
            name = asString(attributes.get("name"));
            profileImage = asString(attributes.get("picture"));
        } else if ("github".equalsIgnoreCase(registrationId)) {
            // GitHub uses 'id' as subject and different field names
            subject = asString(attributes.get("id"));
            email = asString(attributes.get("email"));

            String login = asString(attributes.get("login"));
            if (login != null && !login.isEmpty()) {
                username = login;
            }

            name = asString(attributes.get("name"));
            if (name == null || name.isEmpty()) {
                name = login;
            }

            profileImage = asString(attributes.get("avatar_url"));

            // If email is null, we need to fetch it from GitHub's email API
            if (email == null || email.isEmpty()) {
                // Instead of a synthetic e-mail, call the API
                String realEmail = fetchGitHubPrimaryEmail(userRequest);
                if (realEmail != null) {
                    email = realEmail;
                    log.info("GitHub email successfully fetched via API: {}", email);
                } else {
                    // API'den de e-posta gelmezse, sentetik e-posta kullanmaya devam edebiliriz
                    // OR throw if we enforce the e-mail requirement strictly.
                    if (login != null && !login.isEmpty()) {
                        email = "github_" + subject + "@oauth.local";
                        log.warn("GitHub email still missing; using synthetic email: {}", email);
                    }
                }
            }
        } else {
            // Generic OAuth2 provider
            subject = asString(attributes.get("id"));
            email = asString(attributes.get("email"));
            name = asString(attributes.get("name"));
            profileImage = asString(attributes.get("picture"));
        }

        if (email == null || email.isEmpty()) {
            log.error("Missing email from OAuth2 provider: {}", registrationId);
            throw new OAuth2AuthenticationException("Email is required from OAuth2 provider");
        }

        if (subject == null || subject.isEmpty()) {
            log.error("Missing subject/id from OAuth2 provider: {}", registrationId);
            throw new OAuth2AuthenticationException("Subject/ID is required from OAuth2 provider");
        }

        // Find or create user
        User user = userRepository.findByEmail(email).orElse(null);
        final boolean isNewUser = (user == null);
        if (isNewUser) {
            log.info("Creating new OAuth2 user: {}", email);
            user = new User();
            user.setEmail(email);
            user.setEnabled(true);
            // Initialize roles collection
            user.setRoles(new HashSet<>());
            // Initialize MFA settings
            user.setMfaEnabled(false);
        } else {
            log.info("Found existing user: {}", email);
        }

        log.info("OAuth2User name: {}", name);
        log.info("OAuth2User username: {}", username);
        log.info("OAuth2User email: {}", email);
        log.info("OAuth2User provider: {}", registrationId);
        log.info("OAuth2User subject: {}", subject);

        user.setUsername(username != null && !username.isEmpty() ? username : email);
        user.setName(name != null && !name.isEmpty() ? name : null);
        user.setProfileImage(profileImage != null && !profileImage.isEmpty() ? profileImage : null);
        user.setOauthProvider(registrationId.toLowerCase());
        user.setOauthSubject(subject);

        // Update login tracking
        String clientIp = getClientIpAddress();
        user.setLastLoginIp(clientIp);
        user.setLastLoginAt(Instant.now());
        log.info("Updated login tracking - IP: {}, Time: {}", clientIp, user.getLastLoginAt());

        // Ensure user has USER role
        final String userEmail = email; // Capture for lambda
        if (user.getRoles() == null || user.getRoles().isEmpty()) {
            if (user.getRoles() == null) {
                user.setRoles(new HashSet<>());
            }
            final User finalUser = user;
            roleRepository.findByCode(Role.Code.USER).ifPresent(r -> {
                finalUser.getRoles().add(r);
                log.info("Added USER role to OAuth2 user: {}", userEmail);
            });
        }

        try {
            user = userRepository.save(user);
            log.info("Successfully saved OAuth2 user: {} with ID: {}", user.getUsername(), user.getId());

            // Save last login information for "Continue with this account" feature
            lastLoginInfoService.saveLastLoginInfo(user, registrationId.toLowerCase());
            log.info("Saved last login info for {} with method {}", user.getEmail(), registrationId.toLowerCase());

        } catch (Exception e) {
            log.error("Error saving OAuth2 user: {}", email, e);
            throw new OAuth2AuthenticationException("Failed to save user: " + e.getMessage());
        }

        log.info("===== OAuth2UserService END =====");

        // Build authorities from roles (both role authorities and ROLE_ prefix)
        Set<GrantedAuthority> authorities = new HashSet<>();
        if (user != null && user.getRoles() != null) {
            user.getRoles().forEach(role -> {
                // Add role-specific authorities
                role.getAuthorities()
                        .forEach(authority -> authorities.add(new SimpleGrantedAuthority(authority.getName())));
                // Add ROLE_ prefix for role-based checks
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getCode().name()));
            });
        }

        // Return UNIFIED CustomUserDetails (implements OAuth2User)
        // This ensures consistent principal type across all authentication methods
        return new CustomUserDetails(user, authorities, attributes, null, null);
    }

    private String asString(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    // WebClient Example Method
    // private String fetchGitHubPrimaryEmail(OAuth2UserRequest userRequest) {
    //     String accessToken = userRequest.getAccessToken().getTokenValue();

    //     try {
    //         // Build the API request with WebClient and execute it synchronously (blocking)
    //         // sonucu alma.
    //         JsonNode emailsNode = webClient.get()
    //                 .uri("/user/emails") // Base URL is already defined in WebClientConfig
    //                 .header(HttpHeaders.AUTHORIZATION, "token " + accessToken)
    //                 .retrieve()
    //                 // Throw if the status is not 2xx (e.g. 403, 404)
    //                 .onStatus(HttpStatusCode::isError, clientResponse -> {
    //                     log.error("HTTP error while fetching e-mail from the GitHub API: {}",
    //                             clientResponse.statusCode());
    //                     return Mono.error(new RuntimeException("GitHub API Error"));
    //                 })
    //                 .bodyToMono(JsonNode.class) // Convert the response to JsonNode
    //                 .block(); // Block for the result since we are in a synchronous context

    //         if (emailsNode != null && emailsNode.isArray()) {
    //             for (JsonNode emailNode : emailsNode) {
    //                 // Find the e-mail that is both primary AND verified
    //                 if (emailNode.has("primary") && emailNode.get("primary").asBoolean() &&
    //                         emailNode.has("verified") && emailNode.get("verified").asBoolean()) {

    //                     String primaryEmail = emailNode.get("email").asText();
    //                     log.info("GitHub primary email fetched from API: {}", primaryEmail);
    //                     return primaryEmail;
    //                 }
    //             }
    //         }

    //     } catch (Exception e) {
    //         log.error("Error while fetching the user e-mail from the GitHub API", e);
    //     }

    //     return null;
    // }

    // RestClient Example Method
    private String fetchGitHubPrimaryEmail(OAuth2UserRequest userRequest) {
        String accessToken = userRequest.getAccessToken().getTokenValue();

        try {
            // RestClient is blocking; no need to call block()
            GitHubEmail[] emailsArray = restClient.get()
                    .uri("/user/emails")
                    .header(HttpHeaders.AUTHORIZATION, "token " + accessToken)
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, (req, res) -> {
                        log.error("GitHub API HTTP Error {}", res.getStatusCode());
                        throw new RuntimeException("GitHub API Error");
                    })
                    .body(GitHubEmail[].class);

            if (emailsArray != null) {
                for (GitHubEmail emailData : emailsArray) {
                    // Find the e-mail that is both primary and verified
                    if (emailData.primary() && emailData.verified()) {
                        log.info("GitHub primary email fetched from API: {}", emailData.email());
                        return emailData.email();
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error fetching GitHub primary email", e);
        }

        return null;
    }

    private String getClientIpAddress() {
        try {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder
                    .getRequestAttributes();
            if (attributes != null) {
                HttpServletRequest request = attributes.getRequest();
                return request.getRemoteAddr();
            }
        } catch (Exception e) {
            log.warn("Failed to get client IP address: {}", e.getMessage());
        }
        return "unknown";
    }
}
