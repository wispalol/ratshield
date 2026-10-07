package com.ratshield.update;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Checks a small JSON manifest for a newer RATShield release.
 *
 * <p>The check is a plain HTTPS GET; when the network, DNS or the manifest is
 * unavailable the caller receives the underlying failure and reports it verbatim
 * instead of inventing an outcome.</p>
 */
public final class UpdateChecker {
    public static final String DEFAULT_MANIFEST_URL = "https://ratshield.app/update.json";
    private static final Gson GSON = new Gson();

    public record UpdateInfo(String version, String url, String notes) {
    }

    public record Outcome(boolean reachable, boolean updateAvailable, String detail,
                          UpdateInfo update) {
        public static Outcome failed(String reason) {
            return new Outcome(false, false, reason, null);
        }
    }

    private UpdateChecker() {
    }

    public static String currentVersion() {
        String version = UpdateChecker.class.getPackage().getImplementationVersion();
        return version == null || version.isBlank() ? "1.0.0" : version;
    }

    public static Outcome check(String manifestUrl, String current) {
        HttpRequest request = HttpRequest.newBuilder(URI.create(manifestUrl))
                .timeout(Duration.ofSeconds(6))
                .header("Accept", "application/json")
                .header("User-Agent", "RATShield/" + current)
                .GET()
                .build();
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(6))
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();
            HttpResponse<String> response = client.send(request,
                    HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                return Outcome.failed("Update service answered HTTP " + response.statusCode());
            }
            UpdateInfo info;
            try {
                info = GSON.fromJson(response.body(), UpdateInfo.class);
            } catch (JsonParseException e) {
                return Outcome.failed("Update service returned malformed JSON");
            }
            if (info == null || info.version() == null || info.version().isBlank()) {
                return Outcome.failed("Update manifest did not contain a version");
            }
            return new Outcome(true, isNewer(info.version(), current),
                    "Manifest reports version " + info.version(), info);
        } catch (IOException e) {
            return Outcome.failed("Could not reach " + manifestUrl + ": "
                    + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Outcome.failed("Update check was interrupted");
        } catch (RuntimeException e) {
            return Outcome.failed("Invalid update URL: "
                    + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
        }
    }

    public static Outcome check(String current) {
        return check(DEFAULT_MANIFEST_URL, current);
    }

    public static boolean isNewer(String candidate, String current) {
        return compare(candidate, current) > 0;
    }

    private static int compare(String left, String right) {
        String[] a = tokenize(left);
        String[] b = tokenize(right);
        int shared = Math.min(a.length, b.length);
        for (int i = 0; i < shared; i++) {
            int result = compareToken(a[i], b[i]);
            if (result != 0) {
                return result;
            }
        }
        return Integer.compare(a.length, b.length);
    }

    private static String[] tokenize(String version) {
        if (version == null) {
            return new String[0];
        }
        return version.trim().replace('-', '.').split("\\.");
    }

    private static int compareToken(String left, String right) {
        boolean leftNumber = !left.isEmpty() && left.chars().allMatch(Character::isDigit);
        boolean rightNumber = !right.isEmpty() && right.chars().allMatch(Character::isDigit);
        if (leftNumber && rightNumber) {
            return Long.compare(Long.parseLong(left), Long.parseLong(right));
        }
        if (leftNumber) {
            return 1;
        }
        if (rightNumber) {
            return -1;
        }
        return left.compareToIgnoreCase(right);
    }
}
