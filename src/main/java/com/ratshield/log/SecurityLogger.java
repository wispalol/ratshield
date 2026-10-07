package com.ratshield.log;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Structured security log.
 *
 * <p>Entries are appended as JSON lines (one object per line) so the file stays greppable and
 * never needs a rewrite, and are also kept in a bounded in-memory ring buffer that the UI can
 * render without touching disk.</p>
 */
public final class SecurityLogger implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(SecurityLogger.class.getName());
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

    public record Entry(Instant timestamp, String level, String category, String message) {
    }

    private final Path file;
    private final int maxEntries;
    private final Deque<Entry> ring = new ArrayDeque<>();
    private final Object lock = new Object();

    public SecurityLogger(Path file, int maxEntries) {
        this.file = file;
        this.maxEntries = Math.max(100, maxEntries);
    }

    public void info(String category, String message) {
        write(Level.INFO, category, message);
    }

    public void warn(String category, String message) {
        write(Level.WARNING, category, message);
    }

    public void error(String category, String message) {
        write(Level.SEVERE, category, message);
    }

    public void error(String category, String message, Throwable cause) {
        write(Level.SEVERE, category, message + " :: " + cause.getClass().getSimpleName() + ": "
                + cause.getMessage());
    }

    private void write(Level level, String category, String message) {
        Entry entry = new Entry(Instant.now(), level.getName(), category == null ? "app" : category,
                message == null ? "" : message);
        synchronized (lock) {
            ring.addLast(entry);
            while (ring.size() > maxEntries) {
                ring.removeFirst();
            }
        }
        if (file != null) {
            try {
                if (file.getParent() != null) {
                    Files.createDirectories(file.getParent());
                }
                Files.writeString(file, GSON.toJson(Map.of(
                        "t", entry.timestamp().toString(),
                        "level", entry.level(),
                        "category", entry.category(),
                        "message", entry.message())) + System.lineSeparator(),
                        StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (IOException e) {
                LOG.log(Level.FINE, "security log write failed", e);
            }
        }
    }

    public List<Entry> recent() {
        synchronized (lock) {
            return new ArrayList<>(ring);
        }
    }

    public List<Entry> recent(int limit) {
        synchronized (lock) {
            List<Entry> all = new ArrayList<>(ring);
            int from = Math.max(0, all.size() - Math.max(1, limit));
            return all.subList(from, all.size());
        }
    }

    public Path file() {
        return file;
    }

    public void clearMemory() {
        synchronized (lock) {
            ring.clear();
        }
    }

    @Override
    public void close() {
        clearMemory();
    }
}
