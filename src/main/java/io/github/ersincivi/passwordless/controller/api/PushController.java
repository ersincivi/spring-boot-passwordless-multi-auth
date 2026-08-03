package io.github.ersincivi.passwordless.controller.api;

import java.io.IOException;
import java.time.Duration;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import io.github.ersincivi.passwordless.push.PushMessage;
import io.github.ersincivi.passwordless.push.PushService;
import io.github.ersincivi.passwordless.push.PushSubscriber;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

@RestController
@RequestMapping("/api/push")
@Tag(name = "Push Notifications", description = "Push notification endpoints for real-time messaging")
@SecurityRequirement(name = "bearerAuth")
public class PushController {

    private final PushService pushService;
    private final PushSubscriber subscriber;

    public PushController(PushService pushService, PushSubscriber subscriber) {
        this.pushService = pushService;
        this.subscriber = subscriber;
    }

    @Operation(
        summary = "Send push message",
        description = "Send a push notification message to subscribed clients. " +
                     "Requires ADMIN or SERVICE role.",
        tags = {"Push Notifications"}
    )
    @ApiResponse(responseCode = "202", description = "Message accepted for delivery")
    @PostMapping("/send")
    @PreAuthorize("hasAnyRole('ADMIN','SERVICE')")
    public ResponseEntity<?> send(
            @RequestBody @Parameter(description = "Push message to send", required = true) PushMessage message) {
        pushService.publish(message);
        return ResponseEntity.accepted().build();
    }

    @Operation(
        summary = "Stream push notifications",
        description = "Subscribe to Server-Sent Events (SSE) stream for real-time push notifications. " +
                     "Connection remains open for 30 minutes.",
        tags = {"Push Notifications"}
    )
    @ApiResponse(responseCode = "200", description = "SSE stream established",
        content = @Content(mediaType = MediaType.TEXT_EVENT_STREAM_VALUE))
    @GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter stream() {
        SseEmitter emitter = new SseEmitter(Duration.ofMinutes(30).toMillis());
        final var listener = (java.util.function.Consumer<PushMessage>) msg -> {
            try {
                emitter.send(SseEmitter.event()
                        .name(msg.type())
                        .data(msg)
                        .reconnectTime(3000));
            } catch (IOException e) {
                emitter.completeWithError(e);
            }
        };
        subscriber.on(listener);
        emitter.onCompletion(() -> subscriber.off(listener));
        emitter.onTimeout(() -> subscriber.off(listener));
        return emitter;
    }
}


