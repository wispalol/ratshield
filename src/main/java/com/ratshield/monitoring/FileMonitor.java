package com.ratshield.monitoring;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Recursive file-system monitor built on the JDK {@link WatchService}.
 *
 * <p>Windows delivers several events for a single write, so identical (path, kind) pairs
 * within a short window are collapsed into one callback. Directories created after start are
 * picked up by the watcher itself and by a periodic registration sweep, so newly created
 * download subfolders are monitored without a restart.</p>
 */
public final class FileMonitor {
    private static final Logger LOG = Logger.getLogger(FileMonitor.class.getName());
    private static final long DEBOUNCE_MS = 250;
    private static final int MAX_DEPTH = 12;

    public enum Kind { CREATED, MODIFIED, DELETED }

    public interface Listener {
        void onEvent(Path path, Kind kind);
    }

    private final List<Path> roots;
    private final Set<String> excludedPrefixes;
    private final Map<String, Long> lastFired = new ConcurrentHashMap<>();
    private final Set<WatchKey> keys = ConcurrentHashMap.newKeySet();
    private final AtomicBoolean running = new AtomicBoolean(false);

    private WatchService watchService;
    private Thread watchThread;
    private ScheduledExecutorService sweep;
    private volatile Listener listener;

    public FileMonitor(List<Path> roots, List<String> excludedPrefixes) {
        this.roots = roots == null ? List.of() : roots.stream().filter(Objects::nonNull).toList();
        this.excludedPrefixes = Set.copyOf(excludedPrefixes == null ? List.of() : excludedPrefixes);
    }

    public void setListener(Listener listener) {
        this.listener = listener;
    }

    public void start() {
        if (!running.compareAndSet(false, true)) {
            return;
        }
        try {
            watchService = FileSystems.getDefault().newWatchService();
        } catch (IOException e) {
            running.set(false);
            LOG.log(Level.WARNING, "file monitor could not start", e);
            return;
        }
        for (Path root : roots) {
            registerTree(root);
        }
        watchThread = new Thread(this::watchLoop, "ratshield-file-monitor");
        watchThread.setDaemon(true);
        watchThread.start();
        sweep = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ratshield-file-monitor-sweep");
            t.setDaemon(true);
            return t;
        });
        sweep.scheduleWithFixedDelay(this::sweepRegister, 30, 30, TimeUnit.SECONDS);
    }

    public void stop() {
        if (!running.compareAndSet(true, false)) {
            return;
        }
        if (sweep != null) {
            sweep.shutdownNow();
            sweep = null;
        }
        if (watchThread != null) {
            watchThread.interrupt();
            watchThread = null;
        }
        if (watchService != null) {
            try {
                watchService.close();
            } catch (IOException ignored) {
                // closing a watch service has no useful failure path
            }
            watchService = null;
        }
        keys.clear();
        lastFired.clear();
    }

    public boolean isRunning() {
        return running.get();
    }

    private void registerTree(Path root) {
        if (root == null || !Files.isDirectory(root) || watchService == null) {
            return;
        }
        Path normalized = root.toAbsolutePath().normalize();
        try {
            Files.walkFileTree(normalized, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    if (!running.get()) {
                        return FileVisitResult.TERMINATE;
                    }
                    if (depth(normalized, dir) > MAX_DEPTH) {
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    register(dir);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            LOG.log(Level.FINE, "cannot register watch tree", e);
        }
    }

    private void register(Path dir) {
        try {
            WatchKey key = dir.register(watchService,
                    StandardWatchEventKinds.ENTRY_CREATE,
                    StandardWatchEventKinds.ENTRY_MODIFY,
                    StandardWatchEventKinds.ENTRY_DELETE);
            keys.add(key);
        } catch (IOException | RuntimeException e) {
            LOG.log(Level.FINE, "cannot watch directory", e);
        }
    }

    private void sweepRegister() {
        if (!running.get()) {
            return;
        }
        for (Path root : roots) {
            if (Files.isDirectory(root)) {
                registerTree(root);
            }
        }
        long cutoff = System.currentTimeMillis() - 60_000;
        lastFired.entrySet().removeIf(e -> e.getValue() < cutoff);
    }

    private void watchLoop() {
        while (running.get()) {
            WatchKey key;
            try {
                key = watchService.poll(500, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                if (running.get()) {
                    LOG.log(Level.FINE, "watch service failed", e);
                }
                return;
            }
            if (key == null) {
                continue;
            }
            Path dir = (Path) key.watchable();
            for (WatchEvent<?> event : key.pollEvents()) {
                WatchEvent.Kind<?> kind = event.kind();
                if (kind == StandardWatchEventKinds.OVERFLOW) {
                    continue;
                }
                Object context = event.context();
                if (!(context instanceof Path relative)) {
                    continue;
                }
                Path path = dir.resolve(relative);
                if (excluded(path)) {
                    continue;
                }
                Kind mapped = switch (kind.name()) {
                    case "ENTRY_CREATE" -> Kind.CREATED;
                    case "ENTRY_DELETE" -> Kind.DELETED;
                    default -> Kind.MODIFIED;
                };
                if (mapped != Kind.DELETED && Files.isDirectory(path)) {
                    registerTree(path);
                    continue;
                }
                fire(path, mapped);
            }
            boolean valid = key.reset();
            if (!valid) {
                keys.remove(key);
            }
        }
    }

    private void fire(Path path, Kind kind) {
        if (!debounce(path, kind)) {
            return;
        }
        Listener target = listener;
        if (target != null) {
            try {
                target.onEvent(path, kind);
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, "file monitor listener failed", e);
            }
        }
    }

    private boolean debounce(Path path, Kind kind) {
        String key = kind.name() + "|" + path.toAbsolutePath().normalize().toString().toLowerCase();
        long now = System.currentTimeMillis();
        Long previous = lastFired.get(key);
        if (previous != null && now - previous < DEBOUNCE_MS) {
            return false;
        }
        lastFired.put(key, now);
        if (lastFired.size() > 20_000) {
            lastFired.entrySet().removeIf(e -> now - e.getValue() > 60_000);
        }
        return true;
    }

    private boolean excluded(Path path) {
        String normalized = path.toAbsolutePath().normalize().toString().toLowerCase(java.util.Locale.ROOT);
        for (String prefix : excludedPrefixes) {
            if (normalized.startsWith(prefix.toLowerCase(java.util.Locale.ROOT))) {
                return true;
            }
        }
        String name = path.getFileName() == null ? "" : path.getFileName().toString();
        return name.endsWith(".tmp") || name.endsWith(".crdownload") || name.endsWith(".part");
    }

    private static int depth(Path root, Path dir) {
        Path r = root.toAbsolutePath().normalize();
        Path d = dir.toAbsolutePath().normalize();
        return r.relativize(d).getNameCount();
    }
}
