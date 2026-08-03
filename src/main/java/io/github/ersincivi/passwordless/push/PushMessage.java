package io.github.ersincivi.passwordless.push;

import java.time.Instant;

public record PushMessage(String type, String title, String body, Instant timestamp) {
    public static PushMessage of(String type, String title, String body) {
        return new PushMessage(type, title, body, Instant.now());
    }
}


