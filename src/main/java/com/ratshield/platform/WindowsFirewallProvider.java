package com.ratshield.platform;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Platform boundary for outbound connection blocking.
 *
 * <p>Blocking is performed with Windows Firewall rules scoped to the exact application path,
 * which requires administrator rights. RATShield never claims success when the rule could not
 * be created: {@link Result} carries the underlying command output so the UI can tell the user
 * exactly what happened.</p>
 */
public interface WindowsFirewallProvider {
    record Result(boolean success, boolean requiresElevation, String message) {
    }

    Result blockApplication(Path executable, String reason);

    Result unblockApplication(Path executable);

    boolean elevated();

    List<String> diagnostics();
}
