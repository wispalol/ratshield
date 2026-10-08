package com.ratshield.protection;

import com.ratshield.config.AppConfig;
import com.ratshield.core.BehavioralContext;
import com.ratshield.core.DetectionEngine;
import com.ratshield.core.ThreatVerdict;
import com.ratshield.event.SecurityEvent;
import com.ratshield.event.SecurityEventBus;
import com.ratshield.log.SecurityLogger;
import com.ratshield.monitoring.FileMonitor;
import com.ratshield.monitoring.NetworkMonitor;
import com.ratshield.monitoring.PersistenceMonitor;
import com.ratshield.monitoring.ProcessMonitor;
import com.ratshield.platform.NetworkConnection;
import com.ratshield.platform.ProcessSnapshot;
import com.ratshield.platform.WindowsPersistenceProvider.PersistenceEntry;
import com.ratshield.quarantine.QuarantineService;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Real-time protection: the layer that keeps watching after a scan finishes.
 *
 * <p>File, process, network and auto-start events are analysed on a bounded worker pool so a
 * burst of events (for example an installer unpacking hundreds of files) can never stall the
 * UI or the monitors themselves. Every action taken is published on the event bus and written
 * to the security log with the exact reasons behind it.</p>
 */
public final class RealtimeProtection implements AutoCloseable {
    private static final Duration REHANDLE_WINDOW = Duration.ofSeconds(10);
    private static final Set<String> INTERESTING_EXTENSIONS = Set.of(
            "exe", "dll", "scr", "com", "pif", "cpl", "msi", "msp", "msix", "msixbundle", "sys", "ocx", "ax", "drv",
            "bat", "cmd", "ps1", "psm1", "psd1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
            "jar", "jnlp", "lnk", "reg", "chm", "apk", "bin", "dat", "url", "application", "appx", "appxbundle");

    private final DetectionEngine detectionEngine;
    private final ActionPolicy policy;
    private final AppConfig config;
    private final SecurityEventBus bus;
    private final SecurityLogger log;
    private final BehaviorAnalyzer behaviorAnalyzer;
    private final ProcessMonitor processMonitor;
    private final NetworkMonitor networkMonitor;
    private final PersistenceMonitor persistenceMonitor;
    private final FileMonitor fileMonitor;

    private final Map<String, Instant> handled = new ConcurrentHashMap<>();
    private final Set<String> blockedEvents = ConcurrentHashMap.newKeySet();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private ExecutorService workers;

    public RealtimeProtection(DetectionEngine detectionEngine, ActionPolicy policy,
                              AppConfig config, SecurityEventBus bus, SecurityLogger log,
                              BehaviorAnalyzer behaviorAnalyzer, FileMonitor fileMonitor,
                              ProcessMonitor processMonitor, NetworkMonitor networkMonitor,
                              PersistenceMonitor persistenceMonitor) {
        this.detectionEngine = detectionEngine;
        this.policy = policy;
        this.config = config;
        this.bus = bus;
        this.log = log;
        this.behaviorAnalyzer = behaviorAnalyzer;
        this.fileMonitor = fileMonitor;
        this.processMonitor = processMonitor;
        this.networkMonitor = networkMonitor;
        this.persistenceMonitor = persistenceMonitor;
    }

    public void start() {
        if (!running.compareAndSet(false, true)) {
            return;
        }
        workers = Executors.newFixedThreadPool(Math.max(2,
                Math.min(6, Runtime.getRuntime().availableProcessors())), runnable -> {
            Thread thread = new Thread(runnable, "ratshield-realtime-worker");
            thread.setDaemon(true);
            return thread;
        });
        fileMonitor.setListener(this::onFileEvent);
        processMonitor.setListener(this::onProcess);
        networkMonitor.setListener(this::onNetwork);
        persistenceMonitor.setListener(this::onPersistence);
        if (config.isRealTimeProtection()) {
            fileMonitor.start();
            processMonitor.start();
            networkMonitor.start();
            persistenceMonitor.start();
        }
        log.info("protection", "Real-time protection started (watch roots: "
                + config.getWatchPaths().size() + ")");
    }

    public void stop() {
        if (!running.compareAndSet(true, false)) {
            return;
        }
        fileMonitor.stop();
        processMonitor.stop();
        networkMonitor.stop();
        persistenceMonitor.stop();
        if (workers != null) {
            workers.shutdown();
            workers = null;
        }
        log.info("protection", "Real-time protection stopped");
    }

    /**
     * Applies the current on/off setting without rebuilding the whole protection stack.
     */
    public void applyEnabledState() {
        if (!running.get()) {
            return;
        }
        if (config.isRealTimeProtection()) {
            fileMonitor.start();
            processMonitor.start();
            networkMonitor.start();
            persistenceMonitor.start();
        } else {
            fileMonitor.stop();
            processMonitor.stop();
            networkMonitor.stop();
            persistenceMonitor.stop();
        }
    }

    public boolean isRunning() {
        return running.get();
    }

    public boolean monitorsActive() {
        return fileMonitor.isRunning() || processMonitor.isRunning()
                || networkMonitor.isRunning() || persistenceMonitor.isRunning();
    }

    private void submit(Runnable task) {
        ExecutorService pool = workers;
        if (pool == null || pool.isShutdown()) {
            return;
        }
        try {
            pool.execute(() -> {
                try {
                    task.run();
                } catch (RuntimeException e) {
                    log.error("protection", "real-time handler failed", e);
                }
            });
        } catch (RuntimeException e) {
            log.error("protection", "real-time task rejected", e);
        }
    }

    void onFileEvent(Path path, FileMonitor.Kind kind) {
        if (!config.isRealTimeProtection() || path == null) {
            return;
        }
        submit(() -> handleFile(path, kind));
    }

    void onProcess(ProcessSnapshot process) {
        if (!config.isRealTimeProtection() || process == null) {
            return;
        }
        submit(() -> handleProcess(process));
    }

    void onNetwork(NetworkConnection connection) {
        if (!config.isRealTimeProtection() || connection == null) {
            return;
        }
        submit(() -> handleNetwork(connection));
    }

    void onPersistence(PersistenceEntry entry) {
        if (!config.isRealTimeProtection() || entry == null) {
            return;
        }
        submit(() -> handlePersistence(entry));
    }

    private void handleFile(Path path, FileMonitor.Kind kind) {
        Path normalized = path.toAbsolutePath().normalize();
        if (Files.isDirectory(normalized) || config.isExcluded(normalized)) {
            return;
        }
        if (kind != FileMonitor.Kind.DELETED && kind != FileMonitor.Kind.CREATED && !isInteresting(normalized)) {
            return;
        }
        String handleKey = normalized.toString().toLowerCase(Locale.ROOT);
        Instant previous = handled.get(handleKey);
        Instant now = Instant.now();
        if (previous != null && previous.plus(REHANDLE_WINDOW).isAfter(now)) {
            return;
        }
        handled.put(handleKey, now);
        if (handled.size() > 5000) {
            handled.entrySet().removeIf(e -> e.getValue().plus(REHANDLE_WINDOW).isBefore(now));
        }

        if (kind == FileMonitor.Kind.DELETED) {
            log.info("protection", "Monitored file deleted: " + normalized);
            return;
        }
        if (!Files.isRegularFile(normalized)) {
            return;
        }

        DetectionEngine.Result result = detectionEngine.analyse(normalized, requestFor(normalized));
        ThreatVerdict verdict = result.verdict();
        if (verdict == null) {
            return;
        }
        policy.apply(normalized, verdict, "real-time protection");
    }

    private void handleProcess(ProcessSnapshot process) {
        Map<Long, ProcessSnapshot> context = processMonitor.cachedProcesses();
        ThreatVerdict verdict = behaviorAnalyzer.analyseProcess(process, context);
        if (verdict == null || verdict.risk().score() < config.getWarnScore()) {
            return;
        }
        policy.observe(verdict, "protection", "Process " + process.name() + " (pid " + process.pid() + ")");
        if (verdict.risk().score() >= config.getAutoQuarantineScore()) {
            bus.publish(new SecurityEvent(SecurityEvent.Type.FILE_BLOCKED, Instant.now(),
                    "Running threat requires action",
                    process.displayPath() + " (pid " + process.pid()
                            + ") is running with a risk score of " + verdict.risk().score()
                            + ". Terminate it from the Protection page.",
                    verdict, SecurityEvent.Severity.CRITICAL));
        }
    }

    private void handleNetwork(NetworkConnection connection) {
        ProcessSnapshot owner = processMonitor.cachedProcesses().get(connection.pid());
        String host = connection.hostname();
        if (host == null || host.isBlank()) {
            host = networkMonitor.hostname(connection.remoteAddress()).orElse("");
        }
        ThreatVerdict verdict = behaviorAnalyzer.analyseNetwork(connection, owner, host);
        if (verdict == null || verdict.risk().score() < config.getWarnScore()) {
            return;
        }
        policy.observe(verdict, "protection", "Connection " + connection.endpoint());
    }

    private void handlePersistence(PersistenceEntry entry) {
        ThreatVerdict verdict = behaviorAnalyzer.analysePersistence(entry);
        if (verdict == null || verdict.risk().score() < config.getWarnScore()) {
            log.info("protection", "New auto-start entry: " + entry.name());
            return;
        }
        policy.observe(verdict, "protection", "Auto-start " + entry.name() + " (" + entry.type() + ")");
    }

    /**
     * Analyses a file on demand and applies the same policy as the real-time path, so the UI,
     * the scanner and the monitors cannot diverge in what they do to a file.
     */
    public DetectionEngine.Result analyseAndAct(Path path) {
        DetectionEngine.Result result = detectionEngine.analyse(path, requestFor(path));
        ThreatVerdict verdict = result.verdict();
        if (verdict != null) {
            policy.apply(path, verdict, "manual analysis");
        }
        return result;
    }

    private DetectionEngine.Request requestFor(Path path) {
        BehavioralContext context = new BehavioralContext();
        String lower = path.toAbsolutePath().normalize().toString().toLowerCase(Locale.ROOT);
        context.setInTemp(BehaviorAnalyzer.isTempLocation(lower))
                .setInAppData(BehaviorAnalyzer.isAppDataLocation(lower))
                .setInStartupLocation(BehaviorAnalyzer.isStartupLocation(lower));
        try {
            java.nio.file.attribute.BasicFileAttributes attrs =
                    Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes.class);
            long ageSeconds = Duration.between(attrs.lastModifiedTime().toInstant(), Instant.now()).toSeconds();
            boolean inDownloads = BehaviorAnalyzer.isDownloadsLocation(lower);
            if (inDownloads && ageSeconds <= DetectionEngine.RECENT_DOWNLOAD_SECONDS) {
                context.setRecentlyDownloaded(true, ageSeconds);
            }
        } catch (java.io.IOException | RuntimeException ignored) {
            // metadata unavailable; behaviour simply stays neutral
        }
        DetectionEngine.Request request = DetectionEngine.Request.defaults();
        return request.withBehaviour(context);
    }

    private boolean isInteresting(Path path) {
        String name = path.getFileName() == null ? "" : path.getFileName().toString();
        int dot = name.lastIndexOf('.');
        if (dot > 0 && INTERESTING_EXTENSIONS.contains(name.substring(dot + 1).toLowerCase(Locale.ROOT))) {
            return true;
        }
        byte[] head = readHead(path, 8);
        if (head == null) {
            return false;
        }
        return isExecutableMagic(head) || isScriptLike(head);
    }

    static boolean isExecutableMagic(byte[] head) {
        if (head.length >= 2 && head[0] == 'M' && head[1] == 'Z') {
            return true;
        }
        if (head.length >= 4 && head[0] == 0x7F && head[1] == 'E' && head[2] == 'L' && head[3] == 'F') {
            return true;
        }
        if (head.length >= 4 && head[0] == 'P' && head[1] == 'K'
                && (head[2] == 3 || head[2] == 5 || head[2] == 7)) {
            return true;
        }
        return head.length >= 2 && head[0] == 'M' && head[1] == 'Z';
    }

    static boolean isScriptLike(byte[] head) {
        String text = new String(head, 0, Math.min(head.length, 8), java.nio.charset.StandardCharsets.ISO_8859_1)
                .toLowerCase(Locale.ROOT);
        return text.startsWith("@echo") || text.startsWith("#!") || text.startsWith("powershell")
                || text.startsWith("param(") || text.startsWith("'use strict");
    }

    private static byte[] readHead(Path path, int count) {
        try (java.io.InputStream in = Files.newInputStream(path)) {
            return in.readNBytes(count);
        } catch (Exception e) {
            return null;
        }
    }

    private void publish(SecurityEvent event) {
        bus.publish(event);
    }

    @Override
    public void close() {
        stop();
    }
}
