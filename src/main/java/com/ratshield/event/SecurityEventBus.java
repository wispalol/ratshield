package com.ratshield.event;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Publish/subscribe bus for {@link SecurityEvent}s.
 *
 * <p>Publishing never blocks the producer: listener failures are logged and isolated so one
 * broken subscriber (for example an event handler during UI shutdown) cannot stop protection.</p>
 */
public final class SecurityEventBus {
    private static final Logger LOG = Logger.getLogger(SecurityEventBus.class.getName());

    private final List<Consumer<SecurityEvent>> listeners = new CopyOnWriteArrayList<>();

    public void subscribe(Consumer<SecurityEvent> listener) {
        listeners.add(Objects.requireNonNull(listener));
    }

    public void unsubscribe(Consumer<SecurityEvent> listener) {
        listeners.remove(listener);
    }

    public void publish(SecurityEvent event) {
        if (event == null) {
            return;
        }
        for (Consumer<SecurityEvent> listener : listeners) {
            try {
                listener.accept(event);
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, "event listener failed", e);
            }
        }
    }

    public int subscriberCount() {
        return listeners.size();
    }
}
