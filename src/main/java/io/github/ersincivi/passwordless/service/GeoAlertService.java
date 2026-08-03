package io.github.ersincivi.passwordless.service;

import io.github.ersincivi.passwordless.dto.EmailQueueMessage;
import io.github.ersincivi.passwordless.enums.EmailQueueType;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Locale;
import java.util.UUID;

@Service
public class GeoAlertService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final FindByIndexNameSessionRepository<? extends Session> sessionRepository;
    private final EmailQueueService emailQueueService;
    private final UserService userService;
    private final SecureRandom random = new SecureRandom();

    public GeoAlertService(RedisTemplate<String, Object> redisTemplate,
        FindByIndexNameSessionRepository<? extends Session> sessionRepository,
        EmailQueueService emailQueueService,
        UserService userService) {
        this.redisTemplate = redisTemplate;
        this.sessionRepository = sessionRepository;
        this.emailQueueService = emailQueueService;
        this.userService = userService;
    }

    /**
     * Send geo location alert email with session termination link
     * 
     * @param email User's email address
     * @param username Username
     * @param sessionId Current session ID to invalidate if user denies login
     * @param currentCountry Current login country
     * @param previousCountry Previous login country
     * @param ipAddress IP address of the login
     * @param locale User's locale for i18n
     */
    public void sendGeoAlert(String email, String username, String sessionId, 
                            String currentCountry, String previousCountry, 
                            String ipAddress, Locale locale) {
        // Generate a unique token for this alert
        String alertToken = UUID.randomUUID().toString();
        
        // Store session info with token for 24 hours
        String key = "geo:alert:" + alertToken;
        GeoAlertData data = new GeoAlertData(username, sessionId, currentCountry, previousCountry, ipAddress);
        redisTemplate.opsForValue().set(key, data, Duration.ofHours(24));
        
        // Create email body with alert token embedded
        String emailBody = String.format("%s|%s|%s|%s|%s", 
            alertToken, currentCountry, previousCountry, ipAddress, locale.getLanguage());
        
        String subject = "Security Alert: Login from New Location";
        emailQueueService.enqueue(new EmailQueueMessage(
            email, 
            subject, 
            emailBody, 
            EmailQueueType.GEO_ALERT, 
            locale
        ));
    }

    /**
     * Verify and retrieve geo alert data by token
     */
    public GeoAlertData getAlertData(String token) {
        String key = "geo:alert:" + token;
        Object data = redisTemplate.opsForValue().get(key);
        if (data instanceof GeoAlertData geoData) {
            return geoData;
        }
        return null;
    }

    /**
     * Mark alert as confirmed (user clicked "Yes, it was me")
     */
    public void confirmAlert(String token) {
        userService.updateLastLoginIp(getAlertData(token).username, getAlertData(token).ipAddress);
        String key = "geo:alert:" + token;
        redisTemplate.delete(key);
    }

    /**
     * Mark alert as denied (user clicked "No, it's not me")
     * Returns username to be invalidated
     */
    public String denyAlert(String token) {
        String key = "geo:alert:" + token;
        Object data = redisTemplate.opsForValue().get(key);
        if (data instanceof GeoAlertData geoData) {
            redisTemplate.delete(key);
            return geoData.sessionId;
        }
        return null;
    }

    // public void deleteRedisSessionData(String sessionId) {
    //     String key = "passwordless:sessions:" + sessionId;
    //     redisTemplate.delete(key);
    // }

    public void invalidateSession(String sessionId) {
        sessionRepository.deleteById(sessionId);
    }

    /**
     * Data class to store geo alert information
     */
    public record GeoAlertData(
        String username,
        String sessionId,
        String currentCountry,
        String previousCountry,
        String ipAddress
    ) implements java.io.Serializable {
        private static final long serialVersionUID = 1L;
    }
}
