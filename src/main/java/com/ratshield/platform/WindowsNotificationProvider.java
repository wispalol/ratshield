package com.ratshield.platform;

import java.time.Duration;
import java.util.List;

/**
 * Platform boundary for user notifications.
 *
 * <p>RATShield's primary notification channel is the in-application notification centre, which
 * always works. This provider additionally attempts the native Windows toast API; because an
 * unpackaged application has no registered AppUserModelID the attempt is best effort and any
 * failure is reported instead of being silently ignored.</p>
 */
public interface WindowsNotificationProvider {
    record Delivery(boolean delivered, String message) {
    }

    Delivery notify(String title, String body);

    boolean available();

    List<String> diagnostics();
}
