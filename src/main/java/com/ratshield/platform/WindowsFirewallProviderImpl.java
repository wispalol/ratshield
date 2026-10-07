package com.ratshield.platform;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class WindowsFirewallProviderImpl implements WindowsFirewallProvider {
    private static final String RULE_PREFIX = "RATShield Block ";

    private final List<String> diagnostics = new ArrayList<>();
    private volatile Boolean elevatedCache;
    private volatile Instant elevatedAt = Instant.MIN;

    private static String ruleName(Path executable) {
        String key = executable.toString().toLowerCase(Locale.ROOT);
        return RULE_PREFIX + Integer.toHexString(key.hashCode());
    }

    @Override
    public boolean elevated() {
        if (Instant.now().minus(Duration.ofMinutes(10)).isBefore(elevatedAt) && elevatedCache != null) {
            return elevatedCache;
        }
        boolean elevated = false;
        if (CommandRunner.isWindows()) {
            CommandRunner.Result result = CommandRunner.run(Duration.ofSeconds(10), "net", "session");
            elevated = result.ok();
            if (result.unavailable()) {
                diagnostics.add("cannot determine elevation state: 'net' unavailable");
            }
        }
        elevatedCache = elevated;
        elevatedAt = Instant.now();
        return elevated;
    }

    @Override
    public Result blockApplication(Path executable, String reason) {
        if (!CommandRunner.isWindows()) {
            return new Result(false, false, "Firewall control is only available on Windows");
        }
        if (executable == null || !Files.exists(executable)) {
            return new Result(false, false, "Executable no longer exists: " + executable);
        }
        if (!elevated()) {
            return new Result(false, true,
                    "Administrator privileges are required to create a Windows Firewall rule");
        }
        String name = ruleName(executable);
        String description = (reason == null || reason.isBlank()) ? "Blocked by RATShield" : reason;
        CommandRunner.Result result = CommandRunner.run(Duration.ofSeconds(20), "netsh", "advfirewall",
                "firewall", "add", "rule", "name=" + name, "dir=out", "action=block", "enable=yes",
                "profile=any", "program=" + executable, "description=" + description);
        if (result.unavailable()) {
            return new Result(false, false, "netsh unavailable: " + result.stderr().trim());
        }
        if (!result.ok()) {
            String message = result.stdout().trim().isBlank() ? result.stderr().trim() : result.stdout().trim();
            diagnostics.add("firewall add failed: " + message);
            boolean alreadyExists = message.toLowerCase(Locale.ROOT).contains("exists");
            if (alreadyExists) {
                return new Result(true, false, "An outbound block rule already exists for this application");
            }
            return new Result(false, false, message);
        }
        return new Result(true, false, "Outbound connections blocked for " + executable.getFileName());
    }

    @Override
    public Result unblockApplication(Path executable) {
        if (!CommandRunner.isWindows()) {
            return new Result(false, false, "Firewall control is only available on Windows");
        }
        if (!elevated()) {
            return new Result(false, true,
                    "Administrator privileges are required to remove a Windows Firewall rule");
        }
        CommandRunner.Result result = CommandRunner.run(Duration.ofSeconds(20), "netsh", "advfirewall",
                "firewall", "delete", "rule", "name=" + ruleName(executable));
        if (!result.ok()) {
            String message = result.stdout().trim().isBlank() ? result.stderr().trim() : result.stdout().trim();
            diagnostics.add("firewall delete failed: " + message);
            return new Result(false, false, message);
        }
        return new Result(true, false, "Firewall rule removed for " + executable.getFileName());
    }

    @Override
    public List<String> diagnostics() {
        return List.copyOf(diagnostics);
    }
}
