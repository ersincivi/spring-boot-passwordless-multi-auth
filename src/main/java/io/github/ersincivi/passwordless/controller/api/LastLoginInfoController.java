package io.github.ersincivi.passwordless.controller.api;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.github.ersincivi.passwordless.domain.LastLoginInfo;
import io.github.ersincivi.passwordless.domain.User;
import io.github.ersincivi.passwordless.repository.UserRepository;
import io.github.ersincivi.passwordless.service.LastLoginInfoService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

@RestController
@RequestMapping("/api/last-login")
@Tag(name = "Last Login Info", description = "Endpoints for retrieving user last login information")
@SecurityRequirement(name = "bearerAuth")
public class LastLoginInfoController {

    private static final Logger log = LoggerFactory.getLogger(LastLoginInfoController.class);

    private final LastLoginInfoService lastLoginInfoService;
    private final UserRepository userRepository;

    public LastLoginInfoController(LastLoginInfoService lastLoginInfoService, 
        UserRepository userRepository) {
        this.lastLoginInfoService = lastLoginInfoService;
        this.userRepository = userRepository;
    }

    /**
     * Get last login info for the authenticated user
     */
    @Operation(
        summary = "Get current user last login",
        description = "Get last login information for the authenticated user including " +
                     "login method, timestamp, and profile details.",
        tags = {"Last Login Info"}
    )
    @ApiResponse(responseCode = "200", description = "Last login info retrieved successfully",
        content = @Content(mediaType = "application/json",
            schema = @Schema(example = "{\"email\": \"user@example.com\", \"userName\": \"John Doe\", \"loginMethod\": \"MAGICLINK\", \"profileImageUrl\": \"https://...\", \"lastLoginAt\": \"2025-01-20T10:30:00Z\"}")))
    @GetMapping("/current")
    public ResponseEntity<Map<String, Object>> getCurrentUserLastLogin(
            @Parameter(description = "Authenticated user principal", hidden = true) Principal principal) {
        if (principal == null) {
            return ResponseEntity.ok(null);
        }

        try {
            String username = principal.getName();
            Optional<User> userOpt = userRepository.findByUsername(username)
                    .or(() -> userRepository.findByEmail(username));

            if (userOpt.isEmpty()) {
                return ResponseEntity.ok(null);
            }

            User user = userOpt.get();
            Optional<LastLoginInfo> lastLoginOpt = lastLoginInfoService.getLastLoginInfo(user.getId());

            if (lastLoginOpt.isEmpty()) {
                return ResponseEntity.ok(null);
            }

            LastLoginInfo lastLogin = lastLoginOpt.get();

            Map<String, Object> response = new HashMap<>();
            response.put("email", lastLogin.getEmail());
            response.put("userName", lastLogin.getUserName());
            response.put("loginMethod", lastLogin.getLoginMethod());
            response.put("profileImageUrl", lastLogin.getProfileImageUrl());
            response.put("lastLoginAt", lastLogin.getLastLoginAt());

            log.info("getCurrentUserLastLogin method - login info fetched for user: {}", lastLogin.getUserName());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Error fetching last login info", e);
            return ResponseEntity.ok(null);
        }
    }

    /**
     * Get last login info by email (for pre-login display)
     */
    @Operation(
        summary = "Get last login by email",
        description = "Get last login info by email. " +
                     "Requires authentication to prevent user enumeration and PII disclosure.",
        tags = {"Last Login Info"}
    )
    @ApiResponse(responseCode = "200", description = "Last login info retrieved successfully",
        content = @Content(mediaType = "application/json",
            schema = @Schema(example = "{\"email\": \"user@example.com\", \"userName\": \"John Doe\", \"loginMethod\": \"MAGICLINK\", \"profileImageUrl\": \"https://...\", \"lastLoginAt\": \"2025-01-20T10:30:00Z\"}")))
    @GetMapping
    public ResponseEntity<Map<String, Object>> getLastLoginByEmail(
            @RequestParam(required = false) @Parameter(description = "User email address") String email) {
        if (email == null || email.isBlank()) {
            return ResponseEntity.ok(null);
        }

        try {
            Optional<LastLoginInfo> lastLoginOpt = lastLoginInfoService.getLastLoginInfoByEmail(email);

            if (lastLoginOpt.isEmpty()) {
                return ResponseEntity.ok(null);
            }

            LastLoginInfo lastLogin = lastLoginOpt.get();

            Map<String, Object> response = new HashMap<>();
            response.put("email", lastLogin.getEmail());
            response.put("userName", lastLogin.getUserName());
            response.put("loginMethod", lastLogin.getLoginMethod());
            response.put("profileImageUrl", lastLogin.getProfileImageUrl());
            response.put("lastLoginAt", lastLogin.getLastLoginAt());

            log.info("getLastLoginByEmail method - login info fetched for user: {}", lastLogin.getUserName());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Error fetching last login info by email", e);
            return ResponseEntity.ok(null);
        }
    }
}
