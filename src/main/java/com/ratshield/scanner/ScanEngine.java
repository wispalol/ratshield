package com.ratshield.scanner;

import com.ratshield.config.AppConfig;
import com.ratshield.core.DetectionEngine;
import com.ratshield.core.RecommendedAction;
import com.ratshield.core.ThreatVerdict;
import com.ratshield.platform.SignatureProvider;
import com.ratshield.protection.ActionPolicy;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Multi-threaded scanner.
 *
 * <p>A producer thread walks the target tree and feeds a bounded queue; a small pool of worker
 * threads runs the detection engine over batches. Signature lookups are batched per worker batch
 * so a full drive scan issues one PowerShell call per 32 executables instead of one per file.
 * Workers only exit when the producer has pushed one poison marker per worker or when the user
 * cancels, so an empty queue never ends the scan early.</p>
 *
 * <p>{@link Listener#onFinding(Finding)} is invoked from worker threads and
 * {@link Listener#onProgress(Progress)}/{@link Listener#onComplete(Summary)} from the runner
 * thread; UI listeners must marshal to the JavaFX application thread themselves.</p>
 */
public final class ScanEngine {
    private static final Logger LOG = Logger.getLogger(ScanEngine.class.getName());
    private static final int QUEUE_CAPACITY = 4096;
    private static final int BATCH_SIZE = 32;
    private static final int MAX_DEPTH = 24;
    private static final Set<String> SKIP_DIR_NAMES = Set.of("windows.old", "$recycle.bin",
            "system volume information");

    public enum Type {QUICK, FULL, CUSTOM}

    public record Target(Path path, String label) {
    }

    public record Progress(long scanned, long threats, int quarantined, String currentPath,
                           Duration elapsed, boolean running) {
    }

    public record Finding(Path path, String fileName, long size, ThreatVerdict verdict,
                          boolean quarantined) {
    }

    public record Summary(Type type, Instant started, Instant finished, long scanned, long visited,
                          int threats, int quarantined, List<Finding> findings, boolean cancelled,
                          List<String> errors) {
        public Duration elapsed() {
            if (started == null || finished == null) {
                return Duration.ZERO;
            }
            return Duration.between(started, finished);
        }
    }

    public interface Listener {
        default void onProgress(Progress progress) {
        }

        default void onFinding(Finding finding) {
        }

        default void onComplete(Summary summary) {
        }
    }

    private final DetectionEngine detectionEngine;
    private final ActionPolicy policy;
    private final SignatureProvider signatureProvider;
    private final AppConfig config;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean cancelRequested = new AtomicBoolean(false);
    private final AtomicLong scanned = new AtomicLong();
    private final AtomicLong threats = new AtomicLong();
    private final AtomicLong quarantined = new AtomicLong();
    private volatile String currentPath = "";
    private volatile Thread runner;
    private final AtomicBoolean producerDone = new AtomicBoolean(false);
    private volatile Summary lastSummary;

    public ScanEngine(DetectionEngine detectionEngine, ActionPolicy policy,
                      SignatureProvider signatureProvider, AppConfig config) {
        this.detectionEngine = detectionEngine;
        this.policy = policy;
        this.signatureProvider = signatureProvider;
        this.config = config;
    }

    public boolean isRunning() {
        return running.get();
    }

    public Summary lastSummary() {
        return lastSummary;
    }

    public void cancel() {
        cancelRequested.set(true);
        Thread thread = runner;
        if (thread != null) {
            thread.interrupt();
        }
    }

    public static List<Path> quickTargets() {
        List<Path> candidates = new ArrayList<>();
        String home = System.getProperty("user.home", "");
        if (!home.isBlank()) {
            candidates.add(Path.of(home, "Downloads"));
            candidates.add(Path.of(home, "Desktop"));
            candidates.add(Path.of(home, "Documents"));
            candidates.add(Path.of(home, "AppData", "Roaming", "Microsoft", "Windows",
                    "Start Menu", "Programs", "Startup"));
            candidates.add(Path.of(home, "AppData", "Local", "Temp"));
        }
        String programData = System.getenv("ProgramData");
        if (programData != null && !programData.isBlank()) {
            candidates.add(Path.of(programData, "Microsoft", "Windows", "Start Menu",
                    "Programs", "Startup"));
        }
        List<Path> existing = new ArrayList<>();
        for (Path path : candidates) {
            if (Files.isDirectory(path)) {
                existing.add(path);
            }
        }
        return existing;
    }

    public static List<Path> fullRoots() {
        List<Path> roots = new ArrayList<>();
        for (Path root : java.nio.file.FileSystems.getDefault().getRootDirectories()) {
            if (Files.isDirectory(root)) {
                roots.add(root);
            }
        }
        return roots;
    }

    public void start(Type type, List<Target> targets, Listener listener) {
        if (!running.compareAndSet(false, true)) {
            return;
        }
        cancelRequested.set(false);
        producerDone.set(false);
        scanned.set(0);
        threats.set(0);
        quarantined.set(0);
        currentPath = "";
        Instant started = Instant.now();
        List<String> errors = new ArrayList<>();
        List<Finding> findings = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        int workerCount = Math.max(2, Math.min(6, Runtime.getRuntime().availableProcessors()));
        BlockingQueue<Path> queue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);

        runner = new Thread(() -> run(type, targets, listener, queue, workerCount, started, errors,
                findings, seen), "ratshield-scan-runner");
        runner.setDaemon(true);
        runner.start();
    }

    private void run(Type type, List<Target> targets, Listener listener, BlockingQueue<Path> queue,
                     int workerCount, Instant started, List<String> errors, List<Finding> findings,
                     Set<String> seen) {
        Thread producer = new Thread(() -> produce(targets, queue, seen, errors, workerCount),
                "ratshield-scan-producer");
        producer.setDaemon(true);

        List<Thread> workers = new ArrayList<>(workerCount);
        for (int i = 0; i < workerCount; i++) {
            Thread worker = new Thread(() -> consume(queue, findings, errors, listener),
                    "ratshield-scan-worker-" + i);
            worker.setDaemon(true);
            workers.add(worker);
        }
        workers.forEach(Thread::start);
        producer.start();

        long lastProgress = 0;
        try {
            while (anyAlive(workers)) {
                if (cancelRequested.get() || Thread.currentThread().isInterrupted()) {
                    break;
                }
                long now = System.currentTimeMillis();
                if (now - lastProgress >= 250) {
                    lastProgress = now;
                    emitProgress(listener, started, true);
                }
                sleep(100);
            }
        } finally {
            if (cancelRequested.get()) {
                queue.clear();
                workers.forEach(Thread::interrupt);
                producer.interrupt();
            }
            joinAll(workers, 3000);
            producer.interrupt();
            joinAll(List.of(producer), 1000);
        }

        boolean cancelled = cancelRequested.get();
        Summary summary = new Summary(type, started, Instant.now(), scanned.get(), seen.size(),
                (int) threats.get(), (int) quarantined.get(), List.copyOf(findings), cancelled,
                List.copyOf(errors));
        lastSummary = summary;
        running.set(false);
        runner = null;
        if (listener != null) {
            emitProgress(listener, started, false);
            try {
                listener.onComplete(summary);
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, "scan completion listener failed", e);
            }
        }
    }

    private void emitProgress(Listener listener, Instant started, boolean isRunning) {
        if (listener == null) {
            return;
        }
        try {
            listener.onProgress(new Progress(scanned.get(), threats.get(), (int) quarantined.get(),
                    currentPath, Duration.between(started, Instant.now()), isRunning));
        } catch (RuntimeException e) {
            LOG.log(Level.FINE, "progress listener failed", e);
        }
    }

    private void produce(List<Target> targets, BlockingQueue<Path> queue, Set<String> seen,
                         List<String> errors, int workerCount) {
        for (Target target : targets) {
            if (cancelRequested.get() || Thread.currentThread().isInterrupted()) {
                break;
            }
            Path root = target.path();
            if (root == null) {
                continue;
            }
            if (Files.isRegularFile(root)) {
                enqueue(root, queue, seen);
                continue;
            }
            if (!Files.isDirectory(root)) {
                continue;
            }
            try {
                Files.walkFileTree(root, new SimpleFileVisitor<>() {
                    @Override
                    public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                        if (cancelRequested.get() || Thread.currentThread().isInterrupted()) {
                            return FileVisitResult.TERMINATE;
                        }
                        if (dir.getNameCount() > root.getNameCount() + MAX_DEPTH) {
                            return FileVisitResult.SKIP_SUBTREE;
                        }
                        String lower = dir.toString().toLowerCase(Locale.ROOT);
                        String name = dir.getFileName() == null ? "" : dir.getFileName().toString()
                                .toLowerCase(Locale.ROOT);
                        if (SKIP_DIR_NAMES.contains(name) || config.isExcluded(dir)) {
                            return FileVisitResult.SKIP_SUBTREE;
                        }
                        currentPath = dir.toString();
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                        if (cancelRequested.get() || Thread.currentThread().isInterrupted()) {
                            return FileVisitResult.TERMINATE;
                        }
                        if (attrs.isRegularFile()) {
                            enqueue(file, queue, seen);
                        }
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult visitFileFailed(Path file, IOException exc) {
                        synchronized (errors) {
                            errors.add(file + ": " + exc.getMessage());
                        }
                        return FileVisitResult.CONTINUE;
                    }
                });
            } catch (IOException | RuntimeException e) {
                synchronized (errors) {
                    errors.add(root + ": " + e.getMessage());
                }
                LOG.log(Level.FINE, "scan traversal failed", e);
            }
        }
        producerDone.set(true);
    }

    private void enqueue(Path file, BlockingQueue<Path> queue, Set<String> seen) {
        if (config.isExcluded(file)) {
            return;
        }
        String key = file.toAbsolutePath().normalize().toString().toLowerCase(Locale.ROOT);
        synchronized (seen) {
            if (!seen.add(key)) {
                return;
            }
        }
        try {
            queue.put(file);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void consume(BlockingQueue<Path> queue, List<Finding> findings, List<String> errors,
                         Listener listener) {
        List<Path> batch = new ArrayList<>(BATCH_SIZE);
        try {
            while (!cancelRequested.get()) {
                batch.clear();
                Path first;
                try {
                    first = queue.poll(500, TimeUnit.MILLISECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                if (first == null) {
                    if (producerDone.get()) {
                        return;
                    }
                    continue;
                }
                batch.add(first);
                queue.drainTo(batch, BATCH_SIZE - 1);
                analyseBatch(batch, findings, errors, listener);
            }
        } finally {
            // worker exits; nothing to close
        }
    }

    private void analyseBatch(List<Path> batch, List<Finding> findings, List<String> errors,
                              Listener listener) {
        List<Path> peBatch = new ArrayList<>(batch.size());
        for (Path path : batch) {
            if (looksLikeExecutableFile(path)) {
                peBatch.add(path);
            }
        }
        if (!peBatch.isEmpty()) {
            try {
                signatureProvider.prefetch(peBatch);
            } catch (RuntimeException e) {
                LOG.log(Level.FINE, "signature prefetch failed", e);
            }
        }
        for (Path file : batch) {
            if (cancelRequested.get() || Thread.currentThread().isInterrupted()) {
                return;
            }
            currentPath = file.toString();
            DetectionEngine.Result result;
            try {
                result = detectionEngine.analyse(file, DetectionEngine.Request.defaults());
            } catch (RuntimeException e) {
                synchronized (errors) {
                    errors.add(file + ": " + e.getMessage());
                }
                scanned.incrementAndGet();
                continue;
            }
            scanned.incrementAndGet();
            ThreatVerdict verdict = result.verdict();
            if (verdict == null) {
                continue;
            }
            ActionPolicy.Outcome outcome = policy.apply(file, verdict, "scan");
            boolean noteworthy = verdict.action() != RecommendedAction.ALLOW
                    || verdict.risk().score() >= policy.warnScore();
            if (!noteworthy) {
                continue;
            }
            threats.incrementAndGet();
            if (outcome.quarantined()) {
                quarantined.incrementAndGet();
            }
            Finding finding = new Finding(file,
                    file.getFileName() == null ? file.toString() : file.getFileName().toString(),
                    result.analysis() == null ? 0 : result.analysis().size(), verdict,
                    outcome.quarantined());
            synchronized (findings) {
                findings.add(finding);
            }
            if (listener != null) {
                try {
                    listener.onFinding(finding);
                } catch (RuntimeException e) {
                    LOG.log(Level.FINE, "scan listener failed", e);
                }
            }
        }
    }

    static boolean looksLikeExecutableFile(Path path) {
        String name = path.getFileName() == null ? "" : path.getFileName().toString().toLowerCase(Locale.ROOT);
        int dot = name.lastIndexOf('.');
        if (dot < 0) {
            return false;
        }
        return switch (name.substring(dot + 1)) {
            case "exe", "dll", "sys", "ocx", "cpl", "scr", "msi", "ax", "drv" -> true;
            default -> false;
        };
    }

    private static boolean anyAlive(List<Thread> threads) {
        for (Thread thread : threads) {
            if (thread.isAlive()) {
                return true;
            }
        }
        return false;
    }

    private static void joinAll(List<Thread> threads, long millis) {
        for (Thread thread : threads) {
            try {
                thread.join(millis);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
