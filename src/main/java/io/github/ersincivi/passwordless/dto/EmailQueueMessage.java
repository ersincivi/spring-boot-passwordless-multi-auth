package io.github.ersincivi.passwordless.dto;

import io.github.ersincivi.passwordless.enums.EmailQueueType;
import java.util.Locale;

/**
 * Enhanced EmailQueueMessage with internationalization support
 * Includes locale information for localized email content
 */
public record EmailQueueMessage(
    String to, 
    String subject, 
    String body, 
    EmailQueueType type, 
    Locale locale
) {
    /**
     * Constructor with default English locale for backward compatibility
     */
    public EmailQueueMessage(String to, String subject, String body, EmailQueueType type) {
        this(to, subject, body, type, Locale.ENGLISH);
    }
}