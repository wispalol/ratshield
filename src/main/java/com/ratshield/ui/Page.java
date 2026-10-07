package com.ratshield.ui;

import com.ratshield.event.SecurityEvent;
import javafx.scene.Parent;

/**
 * A single screen of the application shell. Pages are created once and reused;
 * {@link #onShown()} is called every time the user navigates to the page so the
 * page can reload its data.
 */
public interface Page {
    String id();

    String title();

    Parent root();

    default void onShown() {
    }

    default void onHidden() {
    }

    default void onEvent(SecurityEvent event) {
    }
}
