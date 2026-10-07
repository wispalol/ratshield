package com.ratshield.monitoring;

import com.ratshield.platform.NetworkConnection;
import com.ratshield.platform.WindowsNetworkProvider;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Polling network monitor.
 *
 * <p>Connections are diffed by a stable key (protocol, addresses, ports, owning pid, state) so
 * only genuinely new endpoints are reported. Listener sockets that stay open are reported once
 * when they first appear, not on every poll.</p>
 */
public final class NetworkMonitor {
    private static final Logger LOG = Logger.getLogger(NetworkMonitor.class.getName());

    public interface Listener {
        void onNewConnection(NetworkConnection connection);
    }

    private final WindowsNetworkProvider provider;
    private final long intervalSeconds;
    private final Set<String> seen = new HashSet<>();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private ScheduledExecutorService scheduler;
    private volatile Listener listener;
    private volatile boolean initialised;

    public NetworkMonitor(WindowsNetworkProvider provider, long intervalSeconds) {
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
            Thread t = new Thread(r, "ratshield-network-monitor");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleWithFixedDelay(this::tick, 2, intervalSeconds, TimeUnit.SECONDS);
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

    public List<NetworkConnection> current() {
        return provider.connections();
    }

    public java.util.Optional<String> hostname(String address) {
        try {
            return provider.hostname(address);
        } catch (RuntimeException e) {
            return java.util.Optional.empty();
        }
    }

    static String key(NetworkConnection connection) {
        return connection.protocol() + "|" + connection.localAddress() + ":" + connection.localPort()
                + "|" + connection.remoteAddress() + ":" + connection.remotePort() + "|"
                + connection.pid() + "|" + connection.state();
    }

    private void tick() {
        if (!running.get()) {
            return;
        }
        try {
            List<NetworkConnection> connections = provider.connections();
            List<NetworkConnection> fresh = new ArrayList<>();
            Set<String> currentKeys = new HashSet<>();
            for (NetworkConnection connection : connections) {
                String key = key(connection);
                currentKeys.add(key);
                if (!seen.contains(key)) {
                    fresh.add(connection);
                }
            }
            if (!initialised) {
                seen.addAll(currentKeys);
                initialised = true;
                return;
            }
            seen.retainAll(currentKeys);
            seen.addAll(currentKeys);
            Listener target = listener;
            if (fresh.isEmpty() || target == null) {
                return;
            }
            Map<Long, String> hostCache = new HashMap<>();
            for (NetworkConnection connection : fresh) {
                target.onNewConnection(connection);
            }
        } catch (RuntimeException e) {
            LOG.log(Level.FINE, "network monitor tick failed", e);
        }
    }
}
