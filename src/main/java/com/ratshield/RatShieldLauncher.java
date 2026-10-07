package com.ratshield;

import com.ratshield.ui.RatShieldApp;
import javafx.application.Application;

/**
 * Entry point used by the shaded jar and by the jpackage image.
 */
public final class RatShieldLauncher {
    private RatShieldLauncher() {
    }

    public static void main(String[] args) {
        Application.launch(RatShieldApp.class, args);
    }
}
