package io.github.ersincivi.passwordless.push;

import org.springframework.stereotype.Component;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

@Component
public class PushSubscriber {

    private final CopyOnWriteArrayList<Consumer<PushMessage>> listeners = new CopyOnWriteArrayList<>();

    public void on(Consumer<PushMessage> listener) {
        listeners.add(listener);
    }

    public void off(Consumer<PushMessage> listener) {
        listeners.remove(listener);
    }

    public void receive(PushMessage message) {
        for (Consumer<PushMessage> l : listeners) {
            l.accept(message);
        }
    }
}


