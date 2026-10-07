package com.ratshield.monitoring;

import com.ratshield.platform.ProcessSnapshot;
import com.ratshield.platform.WindowsProcessProvider;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Polling process monitor.
 *
 * <p>The JDK cannot watch the Windows process table, so RATShield diffs consecutive snapshots.
 * Cheap enumeration uses {@link ProcessHandle}; expensive enrichment (image path, owner,
 * Authenticode) is fetched only for processes that just appeared, and never for processes that
 * were already running when the monitor started.</p>
 */
public final class ProcessMonitor {
    private static final Logger LOG = Logger.getLogger(ProcessMonitor.class.getName());
    private static final int MAX_ENRICH_PER_TICK = 8;

    public interface Listener {
        void onNewProcess(ProcessSnapshot process);
    }

    private final WindowsProcessProvider provider;
    private final long intervalSeconds;
    private final Map<Long, ProcessSnapshot> known = new ConcurrentHashMap<>();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private ScheduledExecutorService scheduler;
    private volatile Listener listener;
    private volatile boolean initialised;

    public ProcessMonitor(WindowsProcessProvider provider, long intervalSeconds) {
        this.provider = provider;
        this.intervalSeconds = Math.max(1, intervalSeconds);
    }

    public void setListener(Listener listener) {
        this.listener = listener;
    }

    public void start() {
        if (!running.compareAndSet(false, true)) {
            return;
        }
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ratshield-process-monitor");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleWithFixedDelay(this::tick, 1, intervalSeconds, TimeUnit.SECONDS);
    }

    public void stop() {
        if (!running.compareAndSet(true, false)) {
            return;
        }
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
        }
        known.clear();
        initialised = false;
    }

    public boolean isRunning() {
        return running.get();
    }

    public Map<Long, ProcessSnapshot> cachedProcesses() {
        return new HashMap<>(known);
    }

    private void tick() {
        if (!running.get()) {
            return;
        }
        try {
            List<ProcessSnapshot> current = provider.listProcesses(false);
            Map<Long, ProcessSnapshot> next = new HashMap<>();
            for (ProcessSnapshot snapshot : current) {
                next.put(snapshot.pid(), snapshot);
            }
            if (!initialised) {
                known.putAll(next);
                initialised = true;
                return;
            }
            List<ProcessSnapshot> fresh = new ArrayList<>();
            for (Map.Entry<Long, ProcessSnapshot> entry : next.entrySet()) {
                if (!known.containsKey(entry.getKey())) {
                    fresh.add(entry.getValue());
                }
            }
            known.keySet().retainAll(next.keySet());
            known.putAll(next);
            Listener target = listener;
            if (fresh.isEmpty() || target == null) {
                return;
            }
            int enriched = 0;
            for (ProcessSnapshot snapshot : fresh) {
                ProcessSnapshot detailed = snapshot;
                if (enriched < MAX_ENRICH_PER_TICK) {
                    detailed = provider.snapshot(snapshot.pid()).orElse(snapshot);
                    enriched++;
                }
                target.onNewProcess(detailed);
            }
        } catch (RuntimeException e) {
            LOG.log(Level.FINE, "process monitor tick failed", e);
        }
    }
}
