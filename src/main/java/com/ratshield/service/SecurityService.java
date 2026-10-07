package com.ratshield.service;

import com.ratshield.config.AppConfig;
import com.ratshield.core.DetectionEngine;
import com.ratshield.core.ReputationService;
import com.ratshield.core.RiskEngine;
import com.ratshield.core.ThreatVerdict;
import com.ratshield.core.rules.RuleEngine;
import com.ratshield.event.SecurityEvent;
import com.ratshield.event.SecurityEventBus;
import com.ratshield.log.SecurityLogger;
import com.ratshield.monitoring.FileMonitor;
import com.ratshield.monitoring.NetworkMonitor;
import com.ratshield.monitoring.PersistenceMonitor;
import com.ratshield.monitoring.ProcessMonitor;
import com.ratshield.platform.CommandRunner;
import com.ratshield.platform.NetworkConnection;
import com.ratshield.platform.SignatureProvider;
import com.ratshield.platform.WindowsFirewallProvider;
import com.ratshield.platform.WindowsFirewallProviderImpl;
import com.ratshield.platform.WindowsNetworkProvider;
import com.ratshield.platform.WindowsNetworkProviderImpl;
import com.ratshield.platform.WindowsNotificationProvider;
import com.ratshield.platform.WindowsNotificationProviderImpl;
import com.ratshield.platform.WindowsPersistenceProvider;
import com.ratshield.platform.WindowsPersistenceProviderImpl;
import com.ratshield.platform.WindowsProcessProvider;
import com.ratshield.platform.WindowsProcessProviderImpl;
import com.ratshield.platform.WindowsSignatureProvider;
import com.ratshield.protection.ActionPolicy;
import com.ratshield.protection.BehaviorAnalyzer;
import com.ratshield.protection.RealtimeProtection;
import com.ratshield.quarantine.QuarantineService;
import com.ratshield.scanner.ScanEngine;
import com.ratshield.update.UpdateService;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Composition root and lifecycle owner for everything RATShield does.
 *
 * <p>The UI talks only to this service and to the objects it exposes, which keeps threading
 * rules in one place: monitors publish onto the event bus from background threads, the service
 * buffers the most recent events for the dashboard, and every state change reaches the user
 * through the same pipeline of log line + event + optional native notification.</p>
 */
public final class SecurityService implements AutoCloseable {
    private static final long LOG_ROTATE_BYTES = 32L * 1024 * 1024;
    private static final int EVENT_HISTORY = 1000;

    public record Status(boolean running, boolean realTimeActive, int rules, int ruleErrors,
                         int reputationEntries, int quarantined, int threatsSeen,
                         boolean elevated, boolean windows, Instant startedAt, String dataDirectory) {
    }

    private final Path dataDir;
    private final AppConfig config;
    private final SecurityEventBus bus;
    private final SecurityLogger log;
    private final QuarantineService quarantine;
    private final RuleEngine ruleEngine;
    private final ReputationService reputation;
    private final RiskEngine riskEngine;
    private final SignatureProvider signatureProvider;
    private final DetectionEngine detectionEngine;
    private final ActionPolicy actionPolicy;
    private final BehaviorAnalyzer behaviorAnalyzer;
    private final WindowsProcessProvider processProvider;
    private final WindowsNetworkProvider networkProvider;
    private final WindowsPersistenceProvider persistenceProvider;
    private final WindowsFirewallProvider firewallProvider;
    private final WindowsNotificationProvider notificationProvider;
    private final RealtimeProtection protection;
    private final ScanEngine scanEngine;
    private final UpdateService updateService;
    private final List<SecurityEvent> history = new ArrayList<>();
    private final Instant startedAt = Instant.now();

    private volatile boolean started;
    private int threatsSeen;

    private SecurityService(Path dataDir, AppConfig config, SecurityEventBus bus, SecurityLogger log,
                            QuarantineService quarantine, RuleEngine ruleEngine,
                            ReputationService reputation, RiskEngine riskEngine,
                            SignatureProvider signatureProvider, DetectionEngine detectionEngine,
                            ActionPolicy actionPolicy, BehaviorAnalyzer behaviorAnalyzer,
                            WindowsProcessProvider processProvider, WindowsNetworkProvider networkProvider,
                            WindowsPersistenceProvider persistenceProvider,
                            WindowsFirewallProvider firewallProvider,
                            WindowsNotificationProvider notificationProvider,
                            RealtimeProtection protection, ScanEngine scanEngine,
                            UpdateService updateService) {
        this.dataDir = dataDir;
        this.config = config;
        this.bus = bus;
        this.log = log;
        this.quarantine = quarantine;
        this.ruleEngine = ruleEngine;
        this.reputation = reputation;
        this.riskEngine = riskEngine;
        this.signatureProvider = signatureProvider;
        this.detectionEngine = detectionEngine;
        this.actionPolicy = actionPolicy;
        this.behaviorAnalyzer = behaviorAnalyzer;
        this.processProvider = processProvider;
        this.networkProvider = networkProvider;
        this.persistenceProvider = persistenceProvider;
        this.firewallProvider = firewallProvider;
        this.notificationProvider = notificationProvider;
        this.protection = protection;
        this.scanEngine = scanEngine;
        this.updateService = updateService;
    }

    public static SecurityService create(Path dataDir) {
        Objects.requireNonNull(dataDir, "dataDir");
        try {
            Files.createDirectories(dataDir);
            Files.createDirectories(dataDir.resolve("quarantine"));
            Files.createDirectories(dataDir.resolve("rules"));
        } catch (IOException e) {
            throw new IllegalStateException("Cannot create data directory " + dataDir, e);
        }

        AppConfig config = AppConfig.load(dataDir.resolve("config.json"));
        if (config.loadError() != null) {
            System.err.println("RATShield config: " + config.loadError());
        }
        rotateLogIfNeeded(dataDir.resolve("logs").resolve("security-log.jsonl"));
        SecurityEventBus bus = new SecurityEventBus();
        SecurityLogger log = new SecurityLogger(dataDir.resolve("logs").resolve("security-log.jsonl"),
                config.getMaxLogEntries());

        QuarantineService quarantine = new QuarantineService(dataDir.resolve("quarantine"));
        RuleEngine rules = RuleEngine.loadWithUserRules(dataDir.resolve("rules"), RuleEngine.loadDefaults());
        ReputationService reputation = new ReputationService(ReputationService.RemoteConfig.disabled());
        reputation.loadBundled();
        RiskEngine riskEngine = new RiskEngine(config.getAutoQuarantineScore(), config.getWarnScore());
        SignatureProvider signatures = new WindowsSignatureProvider();
        DetectionEngine detectionEngine = new DetectionEngine(rules, reputation, signatures, riskEngine);
        ActionPolicy policy = new ActionPolicy(config, quarantine, bus, log);
        BehaviorAnalyzer behaviorAnalyzer = new BehaviorAnalyzer(riskEngine, signatures);

        WindowsProcessProvider processProvider = new WindowsProcessProviderImpl();
        WindowsNetworkProvider networkProvider = new WindowsNetworkProviderImpl();
        WindowsPersistenceProvider persistenceProvider = new WindowsPersistenceProviderImpl();
        WindowsFirewallProvider firewallProvider = new WindowsFirewallProviderImpl();
        WindowsNotificationProvider notificationProvider = new WindowsNotificationProviderImpl();

        List<Path> watchRoots = config.getWatchPaths().stream().map(Path::of).toList();
        List<String> exclusions = new ArrayList<>(config.getExcludedPaths());
        exclusions.add(dataDir.toString());
        FileMonitor fileMonitor = new FileMonitor(watchRoots, exclusions);
        ProcessMonitor processMonitor = new ProcessMonitor(processProvider,
                Math.max(2, config.getMonitorIntervalSeconds()));
        NetworkMonitor networkMonitor = new NetworkMonitor(networkProvider,
                Math.max(2, config.getMonitorIntervalSeconds()));
        PersistenceMonitor persistenceMonitor = new PersistenceMonitor(persistenceProvider,
                Math.max(1, config.getMonitorIntervalSeconds()));

        RealtimeProtection protection = new RealtimeProtection(detectionEngine, policy, config, bus,
                log, behaviorAnalyzer, fileMonitor, processMonitor, networkMonitor, persistenceMonitor);
        ScanEngine scanEngine = new ScanEngine(detectionEngine, policy, signatures, config);
        UpdateService updateService = new UpdateService(dataDir, config, bus, log);

        return new SecurityService(dataDir, config, bus, log, quarantine, rules, reputation, riskEngine,
                signatures, detectionEngine, policy, behaviorAnalyzer, processProvider, networkProvider,
                persistenceProvider, firewallProvider, notificationProvider, protection, scanEngine,
                updateService);
    }

    public void start() {
        if (started) {
            return;
        }
        started = true;
        bus.subscribe(this::onEvent);
        int purged = quarantine.purgeExpired(config.getQuarantineRetentionDays());
        if (purged > 0) {
            log.info("quarantine", "Purged " + purged + " expired quarantine item(s)");
        }
        if (ruleEngine.loadErrors().isEmpty()) {
            log.info("rules", "Loaded " + ruleEngine.ruleCount() + " detection rules");
        } else {
            log.warn("rules", "Loaded " + ruleEngine.ruleCount() + " rules with "
                    + ruleEngine.loadErrors().size() + " warning(s): "
                    + String.join("; ", ruleEngine.loadErrors()));
        }
        log.info("reputation", "Local reputation database: " + reputation.size() + " hash(es)");
        protection.start();
        bus.publish(SecurityEvent.of(SecurityEvent.Type.SHIELD_TOGGLED, SecurityEvent.Severity.INFO,
                "RATShield started",
                "Real-time protection " + (config.isRealTimeProtection() ? "enabled" : "disabled")));
    }

    public void stop() {
        if (!started) {
            return;
        }
        protection.stop();
        if (scanEngine.isRunning()) {
            scanEngine.cancel();
        }
        started = false;
        log.info("service", "RATShield stopped");
    }

    @Override
    public void close() {
        stop();
        log.close();
    }

    private void onEvent(SecurityEvent event) {
        synchronized (history) {
            history.add(event);
            while (history.size() > EVENT_HISTORY) {
                history.remove(0);
            }
            if (event.verdict() != null && event.type() == SecurityEvent.Type.THREAT_DETECTED) {
                threatsSeen++;
            }
        }
        if (event.severity() == SecurityEvent.Severity.CRITICAL && config.isWindowsNotifications()) {
            try {
                notificationProvider.notify(event.title(), event.message());
            } catch (RuntimeException e) {
                log.error("notify", "native notification failed", e);
            }
        }
    }

    public List<SecurityEvent> recentEvents() {
        synchronized (history) {
            return List.copyOf(history);
        }
    }

    public void setRealTimeEnabled(boolean enabled) {
        if (config.isRealTimeProtection() == enabled) {
            return;
        }
        config.update(c -> c.setRealTimeProtection(enabled));
        protection.applyEnabledState();
        bus.publish(SecurityEvent.of(SecurityEvent.Type.SHIELD_TOGGLED,
                enabled ? SecurityEvent.Severity.INFO : SecurityEvent.Severity.WARNING,
                enabled ? "Real-time protection enabled" : "Real-time protection disabled",
                enabled ? "Files, processes, connections and auto-start entries are being monitored"
                        : "Monitoring is off; scans can still be run manually"));
        log.warn("protection", "Real-time protection " + (enabled ? "enabled" : "disabled") + " by user");
    }

    public Status status() {
        return new Status(started, started && protection.monitorsActive(), ruleEngine.ruleCount(),
                ruleEngine.loadErrors().size(), reputation.size(), quarantine.count(), threatsSeen,
                firewallProvider.elevated(), CommandRunner.isWindows(), startedAt, dataDir.toString());
    }

    public void startScan(ScanEngine.Type type, List<ScanEngine.Target> targets,
                          ScanEngine.Listener listener) {
        if (scanEngine.isRunning()) {
            return;
        }
        List<ScanEngine.Target> effective = targets;
        if (effective == null || effective.isEmpty()) {
            effective = switch (type) {
                case QUICK -> ScanEngine.quickTargets().stream()
                        .map(p -> new ScanEngine.Target(p, p.getFileName() == null ? p.toString()
                                : p.getFileName().toString())).toList();
                case FULL -> ScanEngine.fullRoots().stream()
                        .map(p -> new ScanEngine.Target(p, p.toString())).toList();
                case CUSTOM -> List.of();
            };
        }
        if (effective.isEmpty()) {
            if (listener != null) {
                listener.onComplete(new ScanEngine.Summary(type, Instant.now(), Instant.now(), 0, 0,
                        0, 0, List.of(), false, List.of("No scan targets selected")));
            }
            return;
        }
        bus.publish(SecurityEvent.of(SecurityEvent.Type.SCAN_STARTED, SecurityEvent.Severity.INFO,
                "Scan started",
                type + " scan of " + effective.size() + " location(s)"));
        scanEngine.start(type, effective, new ScanEngine.Listener() {
            @Override
            public void onProgress(ScanEngine.Progress progress) {
                if (listener != null) {
                    listener.onProgress(progress);
                }
            }

            @Override
            public void onFinding(ScanEngine.Finding finding) {
                if (listener != null) {
                    listener.onFinding(finding);
                }
            }

            @Override
            public void onComplete(ScanEngine.Summary summary) {
                bus.publish(SecurityEvent.of(SecurityEvent.Type.SCAN_COMPLETED,
                        summary.threats() > 0 ? SecurityEvent.Severity.WARNING : SecurityEvent.Severity.INFO,
                        summary.cancelled() ? "Scan cancelled" : "Scan complete",
                        summary.scanned() + " file(s), " + summary.threats() + " detection(s), "
                                + summary.quarantined() + " quarantined"));
                log.info("scan", (summary.cancelled() ? "cancelled" : "completed") + " after "
                        + summary.scanned() + " file(s), threats=" + summary.threats());
                if (listener != null) {
                    listener.onComplete(summary);
                }
            }
        });
    }

    public void cancelScan() {
        scanEngine.cancel();
    }

    public WindowsFirewallProvider firewall() {
        return firewallProvider;
    }

    public WindowsNotificationProvider notifications() {
        return notificationProvider;
    }

    public WindowsProcessProvider processProvider() {
        return processProvider;
    }

    public WindowsNetworkProvider networkProvider() {
        return networkProvider;
    }

    public WindowsPersistenceProvider persistenceProvider() {
        return persistenceProvider;
    }

    public void setRealTimeProtectionSetting(boolean value) {
        config.update(c -> c.setRealTimeProtection(value));
    }

    private static void rotateLogIfNeeded(Path logFile) {
        try {
            if (Files.isRegularFile(logFile) && Files.size(logFile) > LOG_ROTATE_BYTES) {
                Files.move(logFile, logFile.resolveSibling("security-log.1.jsonl"),
                        StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException ignored) {
            // logging must never prevent startup
        }
    }

    public AppConfig config() {
        return config;
    }

    public SecurityEventBus events() {
        return bus;
    }

    public SecurityLogger logger() {
        return log;
    }

    public QuarantineService quarantine() {
        return quarantine;
    }

    public DetectionEngine detectionEngine() {
        return detectionEngine;
    }

    public RealtimeProtection protection() {
        return protection;
    }

    public ScanEngine scanner() {
        return scanEngine;
    }

    public BehaviorAnalyzer behaviorAnalyzer() {
        return behaviorAnalyzer;
    }

    public SignatureProvider signatures() {
        return signatureProvider;
    }

    public RuleEngine rules() {
        return ruleEngine;
    }

    public ReputationService reputation() {
        return reputation;
    }

    public RiskEngine riskEngine() {
        return riskEngine;
    }

    public UpdateService updates() {
        return updateService;
    }

    public Path dataDirectory() {
        return dataDir;
    }

    public Duration uptime() {
        return Duration.between(startedAt, Instant.now());
    }

    public boolean isStarted() {
        return started;
    }

    public int threatCount() {
        synchronized (history) {
            return threatsSeen;
        }
    }
}
