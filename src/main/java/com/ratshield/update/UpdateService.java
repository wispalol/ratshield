package com.ratshield.update;

import com.ratshield.config.AppConfig;
import com.ratshield.event.SecurityEvent;
import com.ratshield.event.SecurityEventBus;
import com.ratshield.log.SecurityLogger;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * Checks GitHub for a newer release, downloads the matching installer and hands it off.
 *
 * <p>Two install paths exist: a setup.exe is simply launched (and periodically refreshed while
 * the app runs), while a portable zip is applied over the current application directory by a
 * detached {@link SelfUpdater} process once this JVM has exited.</p>
 */
public final class UpdateService {
    private static final Duration DOWNLOAD_TIMEOUT = Duration.ofMinutes(20);
    private static final int BUFFER = 8192;

    public record CheckResult(boolean reachable, boolean updateAvailable, String detail,
                              GithubReleases.Release release, GithubReleases.Asset installAsset) {
    }

    private final Path dataDir;
    private final AppConfig config;
    private final SecurityEventBus bus;
    private final SecurityLogger log;
    private volatile String notifiedVersion;

    public UpdateService(Path dataDir, AppConfig config, SecurityEventBus bus, SecurityLogger log) {
        this.dataDir = dataDir;
        this.config = config;
        this.bus = bus;
        this.log = log;
    }

    public CheckResult check() {
        String repository = config.getUpdateRepository();
        if (repository == null || repository.isBlank()) {
            return failed("No update repository is configured");
        }
        Optional<GithubReleases.Release> optional;
        try {
            optional = GithubReleases.latest(repository);
        } catch (IllegalArgumentException | IOException e) {
            return failed("Could not reach GitHub releases (" + repository + "): " + message(e));
        }
        if (optional.isEmpty()) {
            return failed("GitHub reports no releases for " + repository);
        }
        GithubReleases.Release release = optional.get();
        boolean newer = UpdateChecker.isNewer(release.version(), UpdateChecker.currentVersion());
        GithubReleases.Asset asset = newer ? GithubReleases.installAsset(release) : null;
        if (newer && !release.version().equals(notifiedVersion)) {
            notifiedVersion = release.version();
            bus.publish(SecurityEvent.of(SecurityEvent.Type.UPDATE_AVAILABLE,
                    SecurityEvent.Severity.INFO,
                    "Update available: RATShield " + release.version(),
                    asset == null || asset.name().isBlank()
                            ? "Release " + release.tag() + " carries no installable package"
                            : "Package: " + asset.name()));
            log.info("update", "Update available: " + release.version());
        }
        String detail = "Latest release: " + release.tag() + " ("
                + release.assets().size() + " artifact(s))";
        return new CheckResult(true, newer, detail, release, asset);
    }

    public void checkBackground() {
        CheckResult result;
        try {
            result = check();
        } catch (RuntimeException e) {
            log.error("update", "background update check failed", e);
            return;
        }
        if (!result.reachable()) {
            log.warn("update", result.detail());
        } else if (!result.updateAvailable()) {
            log.info("update", "up to date: " + result.detail());
        }
    }

    /**
     * Fetches the given asset into the data directory, verifying its SHA-256 digest when the
     * release body listed one. Invokes the progress callback after every buffer-full written.
     */
    public Path download(GithubReleases.Asset asset, Consumer<Long> progress) throws IOException {
        Path dir = dataDir.resolve("update");
        Files.createDirectories(dir);
        String name = safeName(asset.name());
        Path target = dir.resolve(name);
        HttpRequest request = HttpRequest.newBuilder(URI.create(asset.url()))
                .timeout(DOWNLOAD_TIMEOUT)
                .header("Accept", "application/octet-stream")
                .header("User-Agent", "RATShield/" + UpdateChecker.currentVersion())
                .GET()
                .build();
        HttpResponse<InputStream> response;
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(15))
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();
            response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Update download was interrupted", e);
        }
        try (InputStream raw = response.body()) {
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new IOException("Download answered HTTP " + response.statusCode());
            }
            long written = 0;
            try (OutputStream out = Files.newOutputStream(target, StandardOpenOption.TRUNCATE_EXISTING)) {
                byte[] buffer = new byte[BUFFER];
                int read;
                while ((read = raw.read(buffer)) > 0) {
                    out.write(buffer, 0, read);
                    written += read;
                    if (progress != null) {
                        progress.accept(written);
                    }
                }
            }
        } catch (IOException e) {
            Files.deleteIfExists(target);
            throw e;
        }
        String expected = asset.sha256();
        if (expected != null && !expected.isBlank() && !verifySha256(target, expected)) {
            Files.deleteIfExists(target);
            throw new IOException("SHA-256 mismatch for " + name + " (expected " + expected + ")");
        }
        log.info("update", "downloaded " + name + " (" + written(target) + " bytes)");
        return target;
    }

    /**
     * Launches whichever installer matches the downloaded file. Returns only once the installer
     * process has been started, never waiting for it to finish.
     */
    public void installInBackground(Path downloaded, String assetName) {
        String name = downloaded == null ? (assetName == null ? "" : assetName)
                : downloaded.getFileName().toString();
        try {
            if (name.toLowerCase(Locale.ROOT).endsWith(".exe")) {
                bus.publish(SecurityEvent.of(SecurityEvent.Type.UPDATE_STARTED,
                        SecurityEvent.Severity.INFO, "Installing update",
                        "Launching installer - the app will exit once installation starts"));
                new ProcessBuilder(downloaded.toAbsolutePath().toString(), "/SILENT", "/SP-", "/NOCANCEL", "/NORESTART").start();
                log.info("update", "launched installer " + name);
                System.exit(0);
                return;
            }
            if (name.toLowerCase(Locale.ROOT).endsWith(".zip")) {
                bus.publish(SecurityEvent.of(SecurityEvent.Type.UPDATE_STARTED,
                        SecurityEvent.Severity.INFO, "Installing update",
                        "Applying portable package in the background"));
                startSelfUpdater(downloaded.toAbsolutePath());
                log.info("update", "started self-updater for " + name);
                return;
            }
            publishFailed("No supported installer for " + name);
        } catch (IOException e) {
            publishFailed("Could not start installer: " + message(e));
        }
    }

    private void startSelfUpdater(Path zip) throws IOException {
        Path appDir = resolveAppDir();
        Path logFile = dataDir.resolve("update").resolve("self-updater.log");
        java.util.List<String> command = java.util.List.of(
                Path.of(System.getProperty("java.home"), "bin", "java.exe").toString(),
                "-cp", System.getProperty("java.class.path"),
                SelfUpdater.class.getName(),
                String.valueOf(ProcessHandle.current().pid()),
                appDir.toString(),
                zip.toString());
        ProcessBuilder builder = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .redirectOutput(logFile.toFile());
        builder.start();
    }

    static Path resolveAppDir() {
        try {
            Path location = Path.of(UpdateService.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI());
            Path parent = location.getParent();
            if (parent == null) {
                return Path.of(System.getProperty("user.dir"));
            }
            return parent.getParent() == null ? parent : parent.getParent();
        } catch (Exception e) {
            return Path.of(System.getProperty("user.dir"));
        }
    }

    private void publishFailed(String detail) {
        bus.publish(SecurityEvent.of(SecurityEvent.Type.UPDATE_FAILED,
                SecurityEvent.Severity.WARNING, "Update installation failed", detail));
        log.error("update", detail);
    }

    private static boolean verifySha256(Path file, String expected) throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 unavailable", e);
        }
        try (InputStream in = new DigestInputStream(Files.newInputStream(file), digest)) {
            byte[] buffer = new byte[BUFFER];
            while (in.read(buffer) > 0) {
                // digest accumulates as bytes flow through
            }
        }
        return HexFormat.of().formatHex(digest.digest()).equals(expected.toLowerCase(Locale.ROOT));
    }

    private static long written(Path file) {
        try {
            return Files.size(file);
        } catch (IOException e) {
            return -1;
        }
    }

    private static String safeName(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Asset has no file name");
        }
        String cleaned = name.replace('/', '_').replace('\\', '_').replace("..", "_");
        return cleaned.isBlank() ? "update.bin" : cleaned;
    }

    private CheckResult failed(String detail) {
        log.warn("update", detail);
        return new CheckResult(false, false, detail, null, null);
    }

    private static String message(Exception e) {
        return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
    }
}