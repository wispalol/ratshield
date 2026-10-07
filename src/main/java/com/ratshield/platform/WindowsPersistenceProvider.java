package com.ratshield.platform;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/**
 * Platform boundary for Windows persistence mechanism discovery.
 *
 * <p>Implementations must only <em>read</em> system state. Removing or disabling a persistence
 * entry is performed by {@code PersistenceProtection}, which always records rollback
 * information first.</p>
 */
public interface WindowsPersistenceProvider {
    enum EntryType {
        REGISTRY_RUN,
        REGISTRY_RUNONCE,
        STARTUP_FOLDER,
        SCHEDULED_TASK,
        SERVICE,
        WMI_SUBSCRIPTION,
        OTHER
    }

    record PersistenceEntry(String id, EntryType type, String name, String target, String location,
                            String publisher, String source) {
    }

    List<PersistenceEntry> collect();

    List<String> diagnostics();

    default Optional<String> describe() {
        return Optional.empty();
    }

    static String targetPath(String target) {
        if (target == null || target.isBlank()) {
            return "";
        }
        String value = target.trim();
        if (value.startsWith("\"")) {
            int end = value.indexOf('"', 1);
            return end > 0 ? value.substring(1, end) : value.substring(1);
        }
        int space = value.indexOf(' ');
        String candidate = space > 0 ? value.substring(0, space) : value;
        if (candidate.contains("\\")) {
            return candidate;
        }
        return value;
    }

    static boolean looksLikeExecutable(String target) {
        String path = targetPath(target).toLowerCase(java.util.Locale.ROOT);
        return path.endsWith(".exe") || path.endsWith(".bat") || path.endsWith(".cmd") || path.endsWith(".ps1")
                || path.endsWith(".vbs") || path.endsWith(".js") || path.endsWith(".hta") || path.endsWith(".scr")
                || path.endsWith(".com") || path.endsWith(".pif");
    }
}
