package com.ratshield.update;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Reads the latest release of a GitHub repository through the public Releases API.
 *
 * <p>The app deliberately uses the unauthenticated endpoint so a fresh install can check for
 * updates before the user has provided any credentials. GitHub imposes a low rate limit on
 * anonymous API calls, which is fine for the occasional poll this feature performs.</p>
 */
public final class GithubReleases {
    private static final Duration TIMEOUT = Duration.ofSeconds(8);

    public record Asset(String name, String url, long size, String sha256) {
    }

    public record Release(String tag, String version, String notes, List<Asset> assets) {
    }

    private GithubReleases() {
    }

    /**
     * Parses a GitHub release payload into a {@link Release}, resolving SHA-256 digests that are
     * listed against file names in the release body (each line {@code sha256: <file> <hex>}).
     *
     * @throws IllegalArgumentException when the payload is not a release object
     */
    public static Release parse(String json) {
        JsonObject root;
        try {
            root = JsonParser.parseString(json).getAsJsonObject();
        } catch (JsonParseException e) {
            throw new IllegalArgumentException("Release payload is not valid JSON", e);
        }
        if (root == null) {
            throw new IllegalArgumentException("Release payload is empty");
        }
        String tag = text(root, "tag_name");
        String body = text(root, "body");
        List<Asset> assets = new ArrayList<>();
        JsonElement rawAssets = root.get("assets");
        if (rawAssets != null && rawAssets.isJsonArray()) {
            for (JsonElement element : rawAssets.getAsJsonArray()) {
                if (!element.isJsonObject()) {
                    continue;
                }
                JsonObject object = element.getAsJsonObject();
                String name = text(object, "name");
                String url = text(object, "browser_download_url");
                if (name == null || name.isBlank() || url == null || url.isBlank()) {
                    continue;
                }
                long size = 0;
                JsonElement rawSize = object.get("size");
                if (rawSize != null && rawSize.isJsonPrimitive()) {
                    size = rawSize.getAsJsonPrimitive().isNumber() ? rawSize.getAsLong() : 0;
                }
                assets.add(new Asset(name, url, size, digestFor(body, name)));
            }
        }
        String version = versionFromTag(tag);
        if (version.isBlank()) {
            throw new IllegalArgumentException("Release payload has no usable tag_name");
        }
        return new Release(tag, version, body == null ? "" : body, List.copyOf(assets));
    }

    /**
     * Fetches the newest published release for a repository.
     *
     * @return the release, or an empty optional when the repository has no releases
     * @throws IOException when the network, DNS or GitHub answer prevents a result
     */
    public static Optional<Release> latest(String repository) throws IOException {
        HttpRequest request = buildRequest(endpoint(repository, "latest"),
                UpdateChecker.currentVersion());
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(TIMEOUT)
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();
            HttpResponse<String> response = client.send(request,
                    HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 404) {
                return Optional.empty();
            }
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new IOException("GitHub answered HTTP " + response.statusCode()
                        + " for " + repository);
            }
            try {
                return Optional.of(parse(response.body()));
            } catch (IllegalArgumentException e) {
                throw new IOException("GitHub returned an unusable release payload", e);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Update check was interrupted", e);
        }
    }

    public static String versionFromTag(String tag) {
        if (tag == null) {
            return "";
        }
        String value = tag.trim();
        while (!value.isEmpty() && (value.charAt(0) == 'v' || value.charAt(0) == 'V')) {
            value = value.substring(1);
        }
        return value;
    }

    /**
     * Picks the asset that a fresh install of this RATShield version can actually consume:
     * the WiX installer is preferred, then the portable archive, then whatever else exists.
     */
    public static Asset installAsset(Release release) {
        if (release == null || release.assets().isEmpty()) {
            return null;
        }
        Asset installer = firstNamed(release, "ratshield-setup.exe");
        if (installer != null) {
            return installer;
        }
        Asset portable = firstNamedWithSuffix(release, ".zip");
        if (portable != null) {
            return portable;
        }
        return release.assets().get(0);
    }

    private static Asset firstNamed(Release release, String name) {
        for (Asset asset : release.assets()) {
            if (name.equalsIgnoreCase(asset.name())) {
                return asset;
            }
        }
        return null;
    }

    private static Asset firstNamedWithSuffix(Release release, String suffix) {
        for (Asset asset : release.assets()) {
            if (asset.name().toLowerCase(Locale.ROOT).endsWith(suffix)) {
                return asset;
            }
        }
        return null;
    }

    /**
     * Reads {@code sha256: <file> <hex>} lines out of a release body so the downloader can verify
     * the bytes it received before handing them to the installer.
     */
    static String digestFor(String body, String assetName) {
        if (body == null || body.isBlank() || assetName == null) {
            return "";
        }
        for (String rawLine : body.split("\\R")) {
            String line = rawLine.trim();
            if (!line.toLowerCase(Locale.ROOT).startsWith("sha256:")) {
                continue;
            }
            String[] tokens = line.substring("sha256:".length()).trim().split("\\s+");
            if (tokens.length >= 2 && tokens[0].equalsIgnoreCase(assetName)) {
                return tokens[1].toLowerCase(Locale.ROOT);
            }
        }
        return "";
    }

    static String endpoint(String repository, String path) {
        List<String> parts = new ArrayList<>();
        for (String part : repository.split("/")) {
            if (!part.isBlank()) {
                parts.add(part);
            }
        }
        if (parts.size() < 2) {
            throw new IllegalArgumentException("Update repository must be 'owner/repository': "
                    + repository);
        }
        String owner = encode(parts.get(parts.size() - 2));
        String name = encode(parts.get(parts.size() - 1));
        return "https://api.github.com/repos/" + owner + "/" + name + "/releases/" + path;
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static HttpRequest buildRequest(String url, String current) {
        return HttpRequest.newBuilder(URI.create(url))
                .timeout(TIMEOUT)
                .header("Accept", "application/vnd.github+json")
                .header("User-Agent", "RATShield/" + current)
                .GET()
                .build();
    }

    private static String text(JsonObject object, String field) {
        JsonElement element = object.get(field);
        if (element == null || element.isJsonNull()) {
            return null;
        }
        return element.isJsonPrimitive() ? element.getAsString() : null;
    }
}