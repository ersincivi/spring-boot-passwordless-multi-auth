package io.github.ersincivi.passwordless.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import io.github.ersincivi.passwordless.dto.EmailQueueMessage;
import io.github.ersincivi.passwordless.enums.EmailQueueType;

import java.util.Set;

@Service
public class EmailQueueService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final EmailService emailService;
    private final String queueKey;
    private final String delayedQueueKey;
    private final long geoAlertDelayMs;

    public EmailQueueService(RedisTemplate<String, Object> redisTemplate,
            EmailService emailService,
            @Value("${app.queue.email.key:passwordless:queue:email}") String queueKey,
            @Value("${app.queue.email.delayed-key:passwordless:queue:email:delayed}") String delayedQueueKey,
            @Value("${app.queue.email.geo-alert-delay-ms:5000}") long geoAlertDelayMs) {
        this.redisTemplate = redisTemplate;
        this.emailService = emailService;
        this.queueKey = queueKey;
        this.delayedQueueKey = delayedQueueKey;
        this.geoAlertDelayMs = geoAlertDelayMs;
    }

    public void enqueue(EmailQueueMessage message) {
        // Add to delayed queue (5 seconds)
        if (message.type() == EmailQueueType.GEO_ALERT) {
            long deliveryTime = System.currentTimeMillis() + geoAlertDelayMs;
            redisTemplate.opsForZSet().add(delayedQueueKey, message, deliveryTime);
        } else {
            // Add to immediate queue (1 second)
            redisTemplate.opsForList().leftPush(queueKey, message);
        }
    }

    /**
     * Poll immediate queue every 1000ms (default)
     */
    @Scheduled(fixedDelayString = "${app.queue.email.poll-ms:1000}")
    public void poll() {
        Object obj = redisTemplate.opsForList().rightPop(queueKey);
        if (obj instanceof EmailQueueMessage email) {
            emailService.send(email.to(), email.subject(), email.body(), email.type(), email.locale());
        }
    }

    /**
     * Process delayed queue every 1000ms
     * Checks for messages whose delivery time has arrived
     */
    @Scheduled(fixedDelayString = "${app.queue.email.delayed-poll-ms:1000}")
    public void processDelayedQueue() {
        long currentTime = System.currentTimeMillis();
        
        // Get messages that are ready to be sent (score <= currentTime)
        Set<Object> readyMessages = redisTemplate.opsForZSet()
            .rangeByScore(delayedQueueKey, 0, currentTime);
        
        if (readyMessages != null && !readyMessages.isEmpty()) {
            for (Object obj : readyMessages) {
                if (obj instanceof EmailQueueMessage email) {
                    // Send the email
                    emailService.send(email.to(), email.subject(), email.body(), email.type(), email.locale());
                    
                    // Remove from delayed queue
                    redisTemplate.opsForZSet().remove(delayedQueueKey, obj);
                }
            }
        }
    }
}