package io.github.ersincivi.passwordless.controller.web;

import io.github.ersincivi.passwordless.domain.Role;
import io.github.ersincivi.passwordless.domain.User;
import io.github.ersincivi.passwordless.repository.RoleRepository;
import io.github.ersincivi.passwordless.repository.UserRepository;
import io.github.ersincivi.passwordless.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * JSON backend for the /admin/users management page. Lives in the WEB security
 * chain (session + CSRF), /admin/** is restricted to ROLE_ADMIN in
 * SecurityConfig. Passwordless by design: creating a user never involves a
 * password - the new account signs in via magic link / OTP on its e-mail.
 */
@RestController
@RequestMapping("/admin/api/users")
public class AdminUserApiController {

    private static final Logger log = LoggerFactory.getLogger(AdminUserApiController.class);

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserService userService;
    private final RedisTemplate<String, Object> redisTemplate;

    public AdminUserApiController(UserRepository userRepository,
                                  RoleRepository roleRepository,
                                  UserService userService,
                                  RedisTemplate<String, Object> redisTemplate) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.userService = userService;
        this.redisTemplate = redisTemplate;
    }

    // ---------------------------------------------------------------- list

    @GetMapping
    public ResponseEntity<List<Map<String, Object>>> listUsers() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (User u : userRepository.findAll()) {
            out.add(toDto(u));
        }
        out.sort((a, b) -> String.valueOf(a.get("username"))
                .compareToIgnoreCase(String.valueOf(b.get("username"))));
        return ResponseEntity.ok(out);
    }

    // ---------------------------------------------------------------- stats

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> stats() {
        Map<String, Object> stats = new HashMap<>();
        List<User> all = userRepository.findAll();
        stats.put("totalUsers", all.size());
        stats.put("enabledUsers", all.stream().filter(User::isEnabled).count());
        stats.put("mfaUsers", all.stream()
                .filter(u -> Boolean.TRUE.equals(u.getMfaEnabled())).count());
        long sessions = 0;
        try {
            // Count AUTHENTICATED sessions via Spring Session's principal-name
            // index sets. Raw sessions:* keys would overcount: logout leaves the
            // session hash behind with a zeroed lifetime (lazy deletion) and the
            // logout response itself opens a fresh anonymous session - the index,
            // by contrast, is cleaned up immediately on logout.
            Set<String> indexKeys = redisTemplate.keys("spring:session:index:*PRINCIPAL_NAME_INDEX_NAME:*");
            if (indexKeys != null) {
                for (String key : indexKeys) {
                    Long size = redisTemplate.opsForSet().size(key);
                    sessions += size != null ? size : 0;
                }
            }
        } catch (Exception e) {
            log.warn("Admin stats: could not count sessions from Redis: {}", e.getMessage());
        }
        stats.put("activeSessions", sessions);
        return ResponseEntity.ok(stats);
    }

    // --------------------------------------------------------------- create

    public record CreateUserRequest(String name, String username, String email, List<String> roles) {}

    @PostMapping
    public ResponseEntity<?> createUser(@RequestBody CreateUserRequest req) {
        if (req == null || isBlank(req.username()) || isBlank(req.email())) {
            return error(HttpStatus.BAD_REQUEST, "Username and e-mail are required");
        }
        String username = req.username().trim();
        String email = req.email().trim();
        if (userService.userExists(username)) {
            return error(HttpStatus.CONFLICT, "Username already exists");
        }
        if (userService.userExistsByEmail(email)) {
            return error(HttpStatus.CONFLICT, "E-mail already exists");
        }
        Set<Role> roles = resolveRoles(req.roles());
        if (roles.isEmpty()) {
            return error(HttpStatus.BAD_REQUEST, "At least one valid role is required");
        }

        User user = new User();
        user.setName(isBlank(req.name()) ? username : req.name().trim());
        user.setUsername(username);
        user.setEmail(email);
        user.setEnabled(true);
        user.setLastLoginAt(Instant.now());
        user.setLastLoginIp("0:0:0:0:0:0:0:1");
        user.setRoles(roles);
        userService.saveUser(user);
        log.info("Admin created user '{}' with roles {}", username, req.roles());
        return ResponseEntity.status(HttpStatus.CREATED).body(toDto(user));
    }

    // ----------------------------------------------------- enable / disable

    @PostMapping("/{username}/toggle-enabled")
    public ResponseEntity<?> toggleEnabled(@PathVariable String username, Principal principal) {
        if (username.equals(principal.getName())) {
            return error(HttpStatus.BAD_REQUEST, "You cannot disable your own account");
        }
        User user = userRepository.findByUsername(username).orElse(null);
        if (user == null) return error(HttpStatus.NOT_FOUND, "User not found");
        user.setEnabled(!user.isEnabled());
        userService.saveUser(user);
        log.info("Admin {} user '{}'", user.isEnabled() ? "enabled" : "disabled", username);
        return ResponseEntity.ok(toDto(user));
    }

    // ---------------------------------------------------------------- roles

    public record RolesRequest(List<String> roles) {}

    @PostMapping("/{username}/roles")
    public ResponseEntity<?> setRoles(@PathVariable String username,
                                      @RequestBody RolesRequest req, Principal principal) {
        Set<Role> roles = resolveRoles(req != null ? req.roles() : null);
        if (roles.isEmpty()) {
            return error(HttpStatus.BAD_REQUEST, "At least one valid role is required");
        }
        boolean keepsAdmin = roles.stream().anyMatch(r -> r.getCode() == Role.Code.ADMIN);
        if (username.equals(principal.getName()) && !keepsAdmin) {
            return error(HttpStatus.BAD_REQUEST, "You cannot remove your own ADMIN role");
        }
        User user = userRepository.findByUsername(username).orElse(null);
        if (user == null) return error(HttpStatus.NOT_FOUND, "User not found");
        user.setRoles(roles);
        userService.saveUser(user);
        log.info("Admin set roles of '{}' to {}", username, req.roles());
        return ResponseEntity.ok(toDto(user));
    }

    // ------------------------------------------------------------ MFA reset

    @PostMapping("/{username}/mfa-reset")
    public ResponseEntity<?> resetMfa(@PathVariable String username) {
        User user = userRepository.findByUsername(username).orElse(null);
        if (user == null) return error(HttpStatus.NOT_FOUND, "User not found");
        userService.updateMfaTotp(username, null, false);
        log.info("Admin reset TOTP for user '{}'", username);
        user.setMfaEnabled(false);
        return ResponseEntity.ok(toDto(user));
    }

    // -------------------------------------------------------------- helpers

    private Set<Role> resolveRoles(List<String> names) {
        Set<Role> roles = new HashSet<>();
        if (names == null) return roles;
        for (String name : names) {
            try {
                Role.Code code = Role.Code.valueOf(name.trim().toUpperCase());
                roleRepository.findByCode(code).ifPresent(roles::add);
            } catch (IllegalArgumentException ignored) {
                // unknown role name - skip
            }
        }
        return roles;
    }

    private Map<String, Object> toDto(User u) {
        Map<String, Object> m = new HashMap<>();
        m.put("username", u.getUsername());
        m.put("name", u.getName());
        m.put("email", u.getEmail());
        m.put("enabled", u.isEnabled());
        m.put("mfaEnabled", Boolean.TRUE.equals(u.getMfaEnabled()));
        m.put("oauthProvider", u.getOauthProvider());
        m.put("lastLoginAt", u.getLastLoginAt() != null ? u.getLastLoginAt().toString() : null);
        m.put("lastLoginIp", u.getLastLoginIp());
        List<String> roles = new ArrayList<>();
        if (u.getRoles() != null) {
            u.getRoles().forEach(r -> roles.add(r.getCode().name()));
        }
        roles.sort(String::compareTo);
        m.put("roles", roles);
        return m;
    }

    private static boolean isBlank(String s) { return s == null || s.isBlank(); }

    private ResponseEntity<Map<String, Object>> error(HttpStatus status, String message) {
        return ResponseEntity.status(status).body(Map.of("error", true, "message", message));
    }
}
