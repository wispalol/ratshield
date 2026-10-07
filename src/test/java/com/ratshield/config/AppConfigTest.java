package com.ratshield.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppConfigTest {

    @TempDir
    Path temp;

    @Test
    void defaultsAreSafeForAFreshInstall() {
        AppConfig config = AppConfig.defaults();
        assertTrue(config.isRealTimeProtection());
        assertTrue(config.isAutoQuarantine());
        assertFalse(config.isCloudReputation());
        assertTrue(config.isAutoUpdateCheck());
        assertTrue(config.getAutoQuarantineScore() > config.getWarnScore());
        assertFalse(config.getWatchPaths().isEmpty());
        assertNull(config.loadError());
    }

    @Test
    void settingsSurviveAWriteReadCycle() {
        Path file = temp.resolve("data/config.json");
        AppConfig config = AppConfig.load(file);
        config.update(c -> {
            c.setWarnScore(45);
            c.setTheme("light");
            c.setAutoQuarantine(false);
            c.setAutoUpdateCheck(false);
            c.setUpdateRepository("someone/examples");
            c.setExcludedPaths(List.of(temp.toString()));
        });

        AppConfig reloaded = AppConfig.load(file);
        assertEquals(45, reloaded.getWarnScore());
        assertEquals("light", reloaded.getTheme());
        assertFalse(reloaded.isAutoQuarantine());
        assertFalse(reloaded.isAutoUpdateCheck());
        assertEquals("someone/examples", reloaded.getUpdateRepository());
        assertTrue(reloaded.isExcluded(temp.resolve("sub/file.txt")));
        assertFalse(reloaded.isExcluded(Path.of("C:\\Windows\\System32\\notepad.exe")));
        assertNull(reloaded.loadError());
    }

    @Test
    void outOfRangeValuesAreClamped() {
        AppConfig config = AppConfig.load(null);
        config.setWarnScore(999);
        config.setAutoQuarantineScore(1000);
        config.setMaxFileSizeMb(0);
        config.setQuarantineRetentionDays(-5);
        config.setMonitorIntervalSeconds(0);
        config.setMaxLogEntries(1);
        config.normalise();

        assertTrue(config.getAutoQuarantineScore() <= AppConfig.MAX_AUTQUARANTINE);
        assertTrue(config.getWarnScore() < config.getAutoQuarantineScore());
        assertTrue(config.getMaxFileSizeMb() >= 1);
        assertTrue(config.getQuarantineRetentionDays() >= 1);
        assertTrue(config.getMonitorIntervalSeconds() >= 1);
        assertTrue(config.getMaxLogEntries() >= 100);
    }

    @Test
    void invalidJsonFallsBackToDefaults() throws Exception {
        Path file = temp.resolve("broken.json");
        java.nio.file.Files.writeString(file, "{ this is not json");
        AppConfig config = AppConfig.load(file);
        assertTrue(config.getWarnScore() > 0);
        assertTrue(config.loadError() != null && !config.loadError().isBlank());
    }

    @Test
    void listenersAreNotifiedOnChange() {
        AppConfig config = AppConfig.load(temp.resolve("notify.json"));
        AtomicInteger calls = new AtomicInteger();
        config.addListener(c -> calls.incrementAndGet());
        config.update(c -> c.setTheme("light"));
        config.update(c -> c.setTheme("dark"));
        assertEquals(2, calls.get());
    }

    @Test
    void watchedPathsMatchByPrefix() {
        AppConfig config = AppConfig.load(null);
        config.setWatchPaths(List.of(temp.toString()));
        assertTrue(config.isWatched(temp.resolve("Downloads\\file.exe")));
        assertFalse(config.isWatched(Path.of("D:\\somewhere\\else.bin")));
        assertFalse(config.isWatched(null));
    }
}
