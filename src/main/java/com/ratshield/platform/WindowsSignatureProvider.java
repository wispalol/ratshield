package com.ratshield.platform;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.ratshield.core.PeInfo;
import com.ratshield.core.PeParser;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Windows Authenticode verification.
 *
 * <p>Stage 1 is pure Java: the PE certificate table (data directory 4) is inspected to decide
 * whether a signature is even present, which lets RATShield classify unsigned binaries without
 * any subprocess. Stage 2 asks Windows for the authoritative verdict through
 * {@code Get-AuthenticodeSignature}; the result is cached per path/size/mtime so a file is only
 * ever verified once.</p>
 */
public final class WindowsSignatureProvider implements SignatureProvider {
    private record CacheEntry(SignatureInfo info, long size, long modified) {
    }

    private static final int MAX_CACHE = 4000;
    private static final int BATCH_SIZE = 40;
    private static final Duration POWERSHELL_TIMEOUT = Duration.ofSeconds(45);

    private final Map<String, CacheEntry> cache = new LinkedHashMap<>(256, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, CacheEntry> eldest) {
            return size() > MAX_CACHE;
        }
    };
    private final boolean useWindowsCmdlet;
    private volatile String lastError = "";

    public WindowsSignatureProvider() {
        this(CommandRunner.isWindows());
    }

    public WindowsSignatureProvider(boolean useWindowsCmdlet) {
        this.useWindowsCmdlet = useWindowsCmdlet;
    }

    @Override
    public SignatureInfo verify(Path file) {
        PeInfo pe = PeParser.parse(file).orElse(null);
        if (pe == null) {
            return SignatureInfo.unsigned();
        }
        long size = 0;
        long modified = 0;
        try {
            size = Files.size(file);
            modified = Files.getLastModifiedTime(file).toMillis();
        } catch (Exception e) {
            lastError = "cannot stat " + file + ": " + e.getMessage();
        }
        String key = file.toString().toLowerCase(Locale.ROOT);
        synchronized (cache) {
            CacheEntry entry = cache.get(key);
            if (entry != null && entry.size() == size && entry.modified() == modified) {
                return entry.info();
            }
        }
        SignatureInfo info;
        if (!pe.isCertificateTablePresent()) {
            info = new SignatureInfo(false, SignatureInfo.Status.NOT_SIGNED, "", "", null, null,
                    "pe-certificate-table-absent");
        } else if (!useWindowsCmdlet) {
            info = new SignatureInfo(true, SignatureInfo.Status.UNKNOWN, "", "", null, null,
                    "pe-certificate-table-present; platform verifier unavailable");
        } else {
            List<SignatureInfo> results = queryWindows(List.of(file), size, modified);
            info = results.isEmpty()
                    ? new SignatureInfo(true, SignatureInfo.Status.ERROR, "", "", null, null,
                    "windows verifier returned no result")
                    : results.getFirst();
        }
        synchronized (cache) {
            cache.put(key, new CacheEntry(info, size, modified));
        }
        return info;
    }

    @Override
    public void prefetch(List<Path> files) {
        if (!useWindowsCmdlet || files == null || files.isEmpty()) {
            return;
        }
        List<Path> pending = new ArrayList<>();
        for (Path file : files) {
            PeInfo pe = PeParser.parse(file).orElse(null);
            if (pe == null || !pe.isCertificateTablePresent()) {
                continue;
            }
            String key = file.toString().toLowerCase(Locale.ROOT);
            long size = 0;
            long modified = 0;
            try {
                size = Files.size(file);
                modified = Files.getLastModifiedTime(file).toMillis();
            } catch (Exception ignored) {
                continue;
            }
            synchronized (cache) {
                CacheEntry entry = cache.get(key);
                if (entry != null && entry.size() == size && entry.modified() == modified) {
                    continue;
                }
            }
            pending.add(file);
        }
        for (int i = 0; i < pending.size(); i += BATCH_SIZE) {
            List<Path> batch = pending.subList(i, Math.min(pending.size(), i + BATCH_SIZE));
            List<SignatureInfo> results = queryWindows(batch, -1, -1);
            for (int j = 0; j < batch.size(); j++) {
                Path file = batch.get(j);
                SignatureInfo info = j < results.size() ? results.get(j)
                        : new SignatureInfo(true, SignatureInfo.Status.ERROR, "", "", null, null,
                        "windows verifier returned no result");
                try {
                    synchronized (cache) {
                        cache.put(file.toString().toLowerCase(Locale.ROOT),
                                new CacheEntry(info, Files.size(file), Files.getLastModifiedTime(file).toMillis()));
                    }
                } catch (Exception ignored) {
                    // file vanished during verification
                }
            }
        }
    }

    private List<SignatureInfo> queryWindows(List<Path> files, long expectedSize, long expectedModified) {
        List<SignatureInfo> out = new ArrayList<>();
        StringBuilder script = new StringBuilder("$paths = @(");
        for (int i = 0; i < files.size(); i++) {
            if (i > 0) {
                script.append(',');
            }
            script.append("'").append(escape(files.get(i).toString())).append("'");
        }
        script.append("); $res = foreach ($p in $paths) { ");
        script.append("$s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction SilentlyContinue; ");
        script.append("$c = $s.SignerCertificate; ");
        script.append("[pscustomobject]@{ p=$p; st=[string]$s.Status; sg=$(if($c){[string]$c.Subject}else{''}); ");
        script.append("is=$(if($c){[string]$c.Issuer}else{''}); ");
        script.append("nb=$(if($c){$c.NotBefore.ToString('yyyy-MM-ddTHH:mm:ssZ')}else{''}); ");
        script.append("na=$(if($c){$c.NotAfter.ToString('yyyy-MM-ddTHH:mm:ssZ')}else{''}) } }; ");
        script.append("$res | ConvertTo-Json -Compress");
        try {
            CommandRunner.Result result = CommandRunner.run(POWERSHELL_TIMEOUT, "powershell", "-NoProfile",
                    "-NonInteractive", "-Command", script.toString());
            if (result.unavailable()) {
                lastError = "PowerShell unavailable";
                return fallback(files);
            }
            if (!result.ok() || result.stdout().isBlank()) {
                lastError = "signature query failed: " + result.stderr().trim();
                return fallback(files);
            }
            JsonArray array = parseArray(result.stdout());
            Map<String, SignatureInfo> byPath = new LinkedHashMap<>();
            for (JsonElement element : array) {
                if (!element.isJsonObject()) {
                    continue;
                }
                JsonObject obj = element.getAsJsonObject();
                String path = get(obj, "p");
                byPath.put(path.toLowerCase(Locale.ROOT), toInfo(obj));
            }
            for (Path file : files) {
                SignatureInfo info = byPath.get(file.toString().toLowerCase(Locale.ROOT));
                out.add(info == null ? new SignatureInfo(true, SignatureInfo.Status.ERROR, "", "", null, null,
                        "windows verifier returned no result") : info);
            }
        } catch (RuntimeException e) {
            lastError = "signature query parse failed: " + e.getMessage();
            return fallback(files);
        }
        return out;
    }

    private static List<SignatureInfo> fallback(List<Path> files) {
        List<SignatureInfo> out = new ArrayList<>();
        for (Path ignored : files) {
            out.add(SignatureInfo.unavailable("platform verifier unavailable"));
        }
        return out;
    }

    private static SignatureInfo toInfo(JsonObject obj) {
        String status = get(obj, "st");
        SignatureInfo.Status mapped = switch (status.toLowerCase(Locale.ROOT)) {
            case "valid" -> SignatureInfo.Status.VALID;
            case "notsigned" -> SignatureInfo.Status.NOT_SIGNED;
            case "hashmismatch" -> SignatureInfo.Status.HASH_MISMATCH;
            case "nottrusted" -> SignatureInfo.Status.UNTRUSTED;
            case "unknownerror", "notverified" -> SignatureInfo.Status.ERROR;
            default -> SignatureInfo.Status.UNKNOWN;
        };
        Instant notBefore = parseInstant(get(obj, "nb"));
        Instant notAfter = parseInstant(get(obj, "na"));
        return new SignatureInfo(mapped != SignatureInfo.Status.NOT_SIGNED, mapped, get(obj, "sg"),
                get(obj, "is"), notBefore, notAfter, "Get-AuthenticodeSignature");
    }

    private static Instant parseInstant(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static JsonArray parseArray(String json) {
        JsonElement root = JsonParser.parseString(json.trim());
        if (root.isJsonArray()) {
            return root.getAsJsonArray();
        }
        JsonArray array = new JsonArray();
        array.add(root);
        return array;
    }

    private static String get(JsonObject obj, String field) {
        try {
            if (obj.has(field) && obj.get(field).isJsonPrimitive()) {
                return obj.get(field).getAsString();
            }
        } catch (RuntimeException ignored) {
            // fall through
        }
        return "";
    }

    private static String escape(String value) {
        return value.replace("'", "''");
    }

    @Override
    public List<String> diagnostics() {
        return lastError.isBlank() ? List.of() : List.of(lastError);
    }
}
