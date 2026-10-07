package com.ratshield.core;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Local and (optional) remote hash reputation.
 *
 * <p>The remote check is disabled by default. When enabled only the SHA-256 hash of a file is
 * transmitted — never the file itself, its name, or any other content. See PRIVACY.md.</p>
 */
public final class ReputationService {
    public record ReputationHit(String sha256, String label, Severity severity, String source) {
    }

    public record RemoteConfig(boolean enabled, String endpoint) {
        public static RemoteConfig disabled() {
            return new RemoteConfig(false, "");
        }
    }

    private static final Gson GSON = new Gson();
    private final Map<String, ReputationHit> local = new LinkedHashMap<>();
    private final RemoteConfig remote;
    private String lastRemoteError = "";

    public ReputationService(RemoteConfig remote) {
        this.remote = remote == null ? RemoteConfig.disabled() : remote;
        loadBundled();
    }

    public void loadBundled() {
        InputStream in = ReputationService.class.getClassLoader()
                .getResourceAsStream("reputation/hashes.json");
        if (in != null) {
            try (in) {
                readInto(in, "bundled");
            } catch (IOException e) {
                lastRemoteError = "failed to load bundled reputation data: " + e.getMessage();
            }
        }
    }

    public void loadFile(Path file, String source) {
        if (file == null || !Files.isRegularFile(file)) {
            return;
        }
        try (InputStream in = Files.newInputStream(file)) {
            readInto(in, source);
        } catch (IOException e) {
            lastRemoteError = "failed to load reputation file " + file + ": " + e.getMessage();
        }
    }

    @SuppressWarnings("unchecked")
    private void readInto(InputStream in, String source) throws IOException {
        List<Map<String, Object>> entries = GSON.fromJson(new InputStreamReader(in, StandardCharsets.UTF_8),
                new TypeToken<List<Map<String, Object>>>() {
                }.getType());
        if (entries == null) {
            return;
        }
        for (Map<String, Object> entry : entries) {
            Object hash = entry.get("sha256");
            if (hash == null) {
                continue;
            }
            String sha = hash.toString().toLowerCase(Locale.ROOT);
            String label = String.valueOf(entry.getOrDefault("label", "KnownThreat"));
            Severity severity = Severity.valueOf(String.valueOf(entry.getOrDefault("severity", "HIGH")).toUpperCase(Locale.ROOT));
            local.put(sha, new ReputationHit(sha, label, severity, source));
        }
    }

    public int size() {
        return local.size();
    }

    public Optional<ReputationHit> lookup(String sha256) {
        if (sha256 == null || sha256.isEmpty()) {
            return Optional.empty();
        }
        return Optional.ofNullable(local.get(sha256.toLowerCase(Locale.ROOT)));
    }

    public Optional<ReputationHit> lookupRemote(String sha256) {
        if (!remote.enabled() || sha256 == null || sha256.isEmpty() || remote.endpoint().isBlank()) {
            return Optional.empty();
        }
        lastRemoteError = "";
        try {
            URL url = URI.create(remote.endpoint() + (remote.endpoint().contains("?") ? "&" : "?")
                    + "hash=" + sha256.toLowerCase(Locale.ROOT)).toURL();
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(4000);
            connection.setReadTimeout(4000);
            connection.setRequestProperty("User-Agent", "RATShield");
            connection.setRequestMethod("GET");
            int code = connection.getResponseCode();
            if (code != 200) {
                lastRemoteError = "reputation service returned HTTP " + code;
                connection.disconnect();
                return Optional.empty();
            }
            try (InputStream in = connection.getInputStream()) {
                JsonObject json = GSON.fromJson(new InputStreamReader(in, StandardCharsets.UTF_8), JsonObject.class);
                connection.disconnect();
                if (json == null || !json.has("known") || !json.get("known").getAsBoolean()) {
                    return Optional.empty();
                }
                String label = json.has("label") ? json.get("label").getAsString() : "CloudKnownThreat";
                Severity severity = json.has("severity")
                        ? Severity.valueOf(json.get("severity").getAsString().toUpperCase(Locale.ROOT))
                        : Severity.HIGH;
                return Optional.of(new ReputationHit(sha256, label, severity, "cloud"));
            }
        } catch (IOException | RuntimeException e) {
            lastRemoteError = "reputation lookup failed: " + e.getMessage();
            return Optional.empty();
        }
    }

    public String lastRemoteError() {
        return lastRemoteError;
    }

    public RemoteConfig remoteConfig() {
        return remote;
    }
}
