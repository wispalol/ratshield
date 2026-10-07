package com.ratshield.config;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Persisted application settings.
 *
 * <p>The configuration is stored as JSON next to the rest of RATShield's data and is written
 * atomically (temp file + move) so an interrupted write can never leave a corrupt file behind.
 * Every field has a safe default and the loader tolerates missing/unknown fields so settings
 * written by an older build remain readable.</p>
 */
public final class AppConfig {
    public static final int MIN_AUTQUARANTINE = 1;
    public static final int MAX_AUTQUARANTINE = 100;

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    private static final Type LIST_TYPE = new TypeToken<ArrayList<String>>() {
    }.getType();

    private boolean realTimeProtection = true;
    private boolean scanArchives = true;
    private boolean deepInspection = true;
    private boolean verifySignatures = true;
    private boolean cloudReputation = false;
    private boolean windowsNotifications = false;
    private boolean autoQuarantine = true;
    private int autoQuarantineScore = 60;
    private int warnScore = 40;
    private int maxFileSizeMb = 128;
    private int quarantineRetentionDays = 30;
    private int monitorIntervalSeconds = 5;
    private int maxLogEntries = 2000;
    private String theme = "dark";
    private boolean autoUpdateCheck = true;
    private String updateRepository = "wispalol/RatShield";
    private List<String> excludedPaths = new ArrayList<>();
    private List<String> watchPaths = new ArrayList<>();

    private transient Path file;
    private transient final Object lock = new Object();
    private transient final List<Listener> listeners = new ArrayList<>();

    public interface Listener {
        void onConfigChanged(AppConfig config);
    }

    public static AppConfig defaults() {
        AppConfig config = new AppConfig();
        config.watchPaths = defaultWatchPaths();
        return config;
    }

    private static List<String> defaultWatchPaths() {
        List<String> paths = new ArrayList<>();
        String userHome = System.getProperty("user.home", "");
        if (!userHome.isBlank()) {
            paths.add(Path.of(userHome, "Downloads").toString());
            paths.add(Path.of(userHome, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu",
                    "Programs", "Startup").toString());
        }
        String temp = System.getenv("TEMP");
        if (temp != null && !temp.isBlank()) {
            paths.add(temp);
        }
        return paths;
    }

    public static AppConfig load(Path file) {
        AppConfig config = defaults();
        config.file = file;
        if (file != null && Files.isRegularFile(file)) {
            try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                AppConfig loaded = GSON.fromJson(reader, AppConfig.class);
                if (loaded != null) {
                    config = loaded;
                    config.file = file;
                }
            } catch (IOException | RuntimeException e) {
                // fall back to defaults; the caller can inspect diagnostics via loadError
                config.loadError = e.getMessage();
            }
        }
        config.normalise();
        return config;
    }

    private String loadError;

    public String loadError() {
        return loadError;
    }

    public void normalise() {
        autoQuarantineScore = clamp(autoQuarantineScore, 1, 100);
        warnScore = clamp(warnScore, 0, 99);
        if (warnScore > autoQuarantineScore) {
            warnScore = autoQuarantineScore - 1;
        }
        maxFileSizeMb = clamp(maxFileSizeMb, 1, 4096);
        quarantineRetentionDays = clamp(quarantineRetentionDays, 1, 3650);
        monitorIntervalSeconds = clamp(monitorIntervalSeconds, 1, 3600);
        maxLogEntries = clamp(maxLogEntries, 100, 100_000);
        if (theme == null || theme.isBlank()) {
            theme = "dark";
        }
        if (updateRepository == null || updateRepository.isBlank()) {
            updateRepository = "wispalol/RatShield";
        } else {
            updateRepository = updateRepository.trim();
        }
        excludedPaths = dedupe(excludedPaths);
        watchPaths = dedupe(watchPaths);
        if (autoQuarantineScore <= warnScore) {
            autoQuarantineScore = warnScore + 1;
        }
    }

    private static List<String> dedupe(List<String> values) {
        if (values == null) {
            return new ArrayList<>();
        }
        LinkedHashSet<String> set = new LinkedHashSet<>();
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                set.add(value.trim());
            }
        }
        return new ArrayList<>(set);
    }

    private static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }

    public void save() {
        synchronized (lock) {
            if (file == null) {
                return;
            }
            try {
                Path parent = file.getParent();
                if (parent != null) {
                    Files.createDirectories(parent);
                }
                Path temp = file.resolveSibling(file.getFileName() + ".tmp");
                try (Writer writer = Files.newBufferedWriter(temp, StandardCharsets.UTF_8)) {
                    GSON.toJson(this, writer);
                }
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException e) {
                loadError = "config save failed: " + e.getMessage();
            }
        }
    }

    public void update(java.util.function.Consumer<AppConfig> mutator) {
        synchronized (lock) {
            mutator.accept(this);
            normalise();
            save();
        }
        for (Listener listener : List.copyOf(listeners)) {
            listener.onConfigChanged(this);
        }
    }

    public void addListener(Listener listener) {
        listeners.add(Objects.requireNonNull(listener));
    }

    public boolean isExcluded(Path path) {
        if (path == null) {
            return false;
        }
        String normalized = path.toAbsolutePath().normalize().toString().toLowerCase(Locale.ROOT);
        for (String excluded : excludedPaths) {
            String value = excluded.toLowerCase(Locale.ROOT);
            if (normalized.startsWith(value)) {
                return true;
            }
        }
        return false;
    }

    public boolean isWatched(Path path) {
        if (path == null) {
            return false;
        }
        String normalized = path.toAbsolutePath().normalize().toString().toLowerCase(Locale.ROOT);
        for (String watched : watchPaths) {
            String value = watched.toLowerCase(Locale.ROOT);
            if (!value.isBlank() && normalized.startsWith(value)) {
                return true;
            }
        }
        return false;
    }

    public boolean isRealTimeProtection() {
        return realTimeProtection;
    }

    public void setRealTimeProtection(boolean value) {
        this.realTimeProtection = value;
    }

    public boolean isScanArchives() {
        return scanArchives;
    }

    public void setScanArchives(boolean value) {
        this.scanArchives = value;
    }

    public boolean isDeepInspection() {
        return deepInspection;
    }

    public void setDeepInspection(boolean value) {
        this.deepInspection = value;
    }

    public boolean isVerifySignatures() {
        return verifySignatures;
    }

    public void setVerifySignatures(boolean value) {
        this.verifySignatures = value;
    }

    public boolean isCloudReputation() {
        return cloudReputation;
    }

    public void setCloudReputation(boolean value) {
        this.cloudReputation = value;
    }

    public boolean isWindowsNotifications() {
        return windowsNotifications;
    }

    public void setWindowsNotifications(boolean value) {
        this.windowsNotifications = value;
    }

    public boolean isAutoQuarantine() {
        return autoQuarantine;
    }

    public void setAutoQuarantine(boolean value) {
        this.autoQuarantine = value;
    }

    public int getAutoQuarantineScore() {
        return autoQuarantineScore;
    }

    public void setAutoQuarantineScore(int value) {
        this.autoQuarantineScore = value;
    }

    public int getWarnScore() {
        return warnScore;
    }

    public void setWarnScore(int value) {
        this.warnScore = value;
    }

    public int getMaxFileSizeMb() {
        return maxFileSizeMb;
    }

    public void setMaxFileSizeMb(int value) {
        this.maxFileSizeMb = value;
    }

    public int getQuarantineRetentionDays() {
        return quarantineRetentionDays;
    }

    public void setQuarantineRetentionDays(int value) {
        this.quarantineRetentionDays = value;
    }

    public int getMonitorIntervalSeconds() {
        return monitorIntervalSeconds;
    }

    public void setMonitorIntervalSeconds(int value) {
        this.monitorIntervalSeconds = value;
    }

    public int getMaxLogEntries() {
        return maxLogEntries;
    }

    public void setMaxLogEntries(int value) {
        this.maxLogEntries = value;
    }

    public String getTheme() {
        return theme;
    }

    public void setTheme(String value) {
        this.theme = value;
    }

    public List<String> getExcludedPaths() {
        return excludedPaths;
    }

    public void setExcludedPaths(List<String> values) {
        this.excludedPaths = dedupe(values);
    }

    public List<String> getWatchPaths() {
        return watchPaths;
    }

    public void setWatchPaths(List<String> values) {
        this.watchPaths = dedupe(values);
    }

    public boolean isAutoUpdateCheck() {
        return autoUpdateCheck;
    }

    public void setAutoUpdateCheck(boolean value) {
        this.autoUpdateCheck = value;
    }

    public String getUpdateRepository() {
        return updateRepository;
    }

    public void setUpdateRepository(String value) {
        this.updateRepository = value == null ? "wispalol/RatShield" : value.trim();
    }

    public Instant savedAt() {
        return Instant.now();
    }
}
