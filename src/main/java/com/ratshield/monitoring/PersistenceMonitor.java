package com.ratshield.monitoring;

import com.ratshield.platform.WindowsPersistenceProvider;
import com.ratshield.platform.WindowsPersistenceProvider.PersistenceEntry;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Polling persistence monitor.
 *
 * <p>Windows registry keys, scheduled tasks and services have no change-notification API that a
 * non-privileged process can subscribe to, so RATShield collects the full set periodically and
 * reports entries that were not present in the previous collection.</p>
 */
public final class PersistenceMonitor {
    private static final Logger LOG = Logger.getLogger(PersistenceMonitor.class.getName());

    public interface Listener {
        void onNewPersistence(PersistenceEntry entry);
    }

    private final WindowsPersistenceProvider provider;
    private final long intervalSeconds;
    private final Set<String> seen = new HashSet<>();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private ScheduledExecutorService scheduler;
    private volatile Listener listener;
    private volatile boolean initialised;

    public PersistenceMonitor(WindowsPersistenceProvider provider, long intervalSeconds) {
        this.provider = provider;
        this.intervalSeconds = Math.max(5, intervalSeconds);
    }

    public void setListener(Listener listener) {
        this.listener = listener;
    }

    public void start() {
        if (!running.compareAndSet(false, true)) {
            return;
        }
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ratshield-persistence-monitor");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleWithFixedDelay(this::tick, 5, intervalSeconds * 6L, TimeUnit.SECONDS);
    }

    public void stop() {
        if (!running.compareAndSet(true, false)) {
            return;
        }
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
        }
        seen.clear();
        initialised = false;
    }

    public boolean isRunning() {
        return running.get();
    }

    public List<PersistenceEntry> current() {
        return provider.collect();
    }

    private void tick() {
        if (!running.get()) {
            return;
        }
        try {
            List<PersistenceEntry> entries = provider.collect();
            Set<String> currentIds = new HashSet<>();
            for (PersistenceEntry entry : entries) {
                currentIds.add(entry.id());
            }
            if (!initialised) {
                seen.addAll(currentIds);
                initialised = true;
                return;
            }
            Listener target = listener;
            for (PersistenceEntry entry : entries) {
                if (!seen.contains(entry.id()) && target != null) {
                    target.onNewPersistence(entry);
                }
            }
            seen.clear();
            seen.addAll(currentIds);
        } catch (RuntimeException e) {
            LOG.log(Level.FINE, "persistence monitor tick failed", e);
        }
    }
}
