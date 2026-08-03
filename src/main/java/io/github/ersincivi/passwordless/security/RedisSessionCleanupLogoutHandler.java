package io.github.ersincivi.passwordless.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.stereotype.Component;

/**
 * Removes the session's Redis keys eagerly on logout.
 *
 * Spring Session's deleteById cleans the principal index immediately but
 * leaves the session hash behind with a zeroed lifetime ("lazy deletion") -
 * harmless security-wise, yet the orphaned key lingers until its original
 * TTL passes and skews any raw sessions:* inspection.
 *
 * Order matters: deleteById must run FIRST (it needs the hash to find the
 * principal for index cleanup), only then is the leftover hash deleted.
 * The default SecurityContextLogoutHandler's invalidate() afterwards finds
 * nothing left and no-ops.
 */
@Component
public class RedisSessionCleanupLogoutHandler implements LogoutHandler {

    private static final Logger log = LoggerFactory.getLogger(RedisSessionCleanupLogoutHandler.class);

    private final FindByIndexNameSessionRepository<? extends Session> sessionRepository;
    private final RedisTemplate<String, Object> redisTemplate;

    public RedisSessionCleanupLogoutHandler(
            FindByIndexNameSessionRepository<? extends Session> sessionRepository,
            RedisTemplate<String, Object> redisTemplate) {
        this.sessionRepository = sessionRepository;
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response,
                       Authentication authentication) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return;
        }
        String id = session.getId();
        try {
            // 1. Proper Spring Session teardown: principal index + expires key
            sessionRepository.deleteById(id);
            // 2. Remove the lazily-kept session hash outright
            redisTemplate.delete("spring:session:sessions:" + id);
            redisTemplate.delete("spring:session:sessions:expires:" + id);
            log.debug("Logout: removed Redis session keys for {}", id);
        } catch (Exception e) {
            // Never block a logout on Redis housekeeping
            log.warn("Logout: could not remove Redis session keys for {}: {}", id, e.getMessage());
        }
    }
}
