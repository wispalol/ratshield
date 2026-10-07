package com.ratshield.quarantine;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.ratshield.core.ThreatVerdict;
import com.ratshield.core.HashEngine;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Quarantine storage.
 *
 * <p>A quarantined file is <em>copied</em> into RATShield's private quarantine directory and the
 * original is then removed, so nothing in quarantine can be launched by double-click, by a
 * shell association, or by another process scanning the original folder. Each item keeps a JSON
 * metadata record with the original path, hashes, risk score and threat name so it can be
 * restored byte-for-byte later.</p>
 */
public final class QuarantineService {
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
    private static final Type MAP_TYPE = new TypeToken<LinkedHashMap<String, Object>>() {
    }.getType();

    public record QuarantineRecord(
            String id,
            String originalPath,
            String fileName,
            String sha256,
            long sizeBytes,
            String threatName,
            int riskScore,
            String riskLevel,
            String reasons,
            Instant quarantinedAt
    ) {
    }

    public record Result(boolean success, String message, String id) {
    }

    private final Path directory;
    private final Object lock = new Object();

    public QuarantineService(Path directory) {
        this.directory = directory;
    }

    public Path directory() {
        return directory;
    }

    public Result quarantine(Path file, ThreatVerdict verdict) {
        if (file == null || !Files.isRegularFile(file)) {
            return new Result(false, "File no longer exists: " + file, null);
        }
        synchronized (lock) {
            try {
                Files.createDirectories(directory);
                String sha256 = HashEngine.sha256(file);
                if (sha256 == null) {
                    return new Result(false, "Cannot hash file for quarantine: " + file, null);
                }
                String id = sha256.substring(0, Math.min(24, sha256.length())) + "-"
                        + System.currentTimeMillis();
                Path blob = directory.resolve(id + ".bin");
                Path meta = directory.resolve(id + ".json");
                Files.copy(file, blob, StandardCopyOption.COPY_ATTRIBUTES);

                Map<String, Object> record = new LinkedHashMap<>();
                record.put("id", id);
                record.put("originalPath", file.toAbsolutePath().toString());
                record.put("fileName", file.getFileName() == null ? file.toString()
                        : file.getFileName().toString());
                record.put("sha256", sha256);
                record.put("sizeBytes", Files.size(blob));
                record.put("threatName", verdict == null ? "unknown" : verdict.detectionName());
                record.put("riskScore", verdict == null ? 0 : verdict.risk().score());
                record.put("riskLevel", verdict == null ? "unknown" : verdict.risk().level().name());
                record.put("reasons", verdict == null ? "" : verdict.risk().explain());
                record.put("quarantinedAt", Instant.now().toString());
                Files.writeString(meta, GSON.toJson(record), StandardCharsets.UTF_8);

                try {
                    Files.deleteIfExists(file);
                } catch (IOException deleteFailure) {
                    Files.deleteIfExists(blob);
                    Files.deleteIfExists(meta);
                    return new Result(false,
                            "Quarantine aborted, original file could not be removed: "
                                    + deleteFailure.getMessage(), null);
                }
                return new Result(true, "Moved to quarantine: " + record.get("fileName"), id);
            } catch (IOException e) {
                return new Result(false, "Quarantine failed: " + e.getMessage(), null);
            }
        }
    }

    public List<QuarantineRecord> list() {
        List<QuarantineRecord> records = new ArrayList<>();
        synchronized (lock) {
            if (!Files.isDirectory(directory)) {
                return records;
            }
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory, "*.json")) {
                for (Path meta : stream) {
                    QuarantineRecord record = read(meta);
                    if (record != null) {
                        records.add(record);
                    }
                }
            } catch (IOException e) {
                return records;
            }
        }
        records.sort(Comparator.comparing(QuarantineRecord::quarantinedAt,
                Comparator.nullsLast(Comparator.reverseOrder())));
        return records;
    }

    private QuarantineRecord read(Path meta) {
        try {
            Map<String, Object> raw = GSON.fromJson(Files.readString(meta, StandardCharsets.UTF_8), MAP_TYPE);
            if (raw == null) {
                return null;
            }
            Path blob = directory.resolve(asString(raw.get("id")) + ".bin");
            if (!Files.isRegularFile(blob)) {
                return null;
            }
            return new QuarantineRecord(
                    asString(raw.get("id")),
                    asString(raw.get("originalPath")),
                    asString(raw.get("fileName")),
                    asString(raw.get("sha256")),
                    asLong(raw.get("sizeBytes")),
                    asString(raw.get("threatName")),
                    (int) asLong(raw.get("riskScore")),
                    asString(raw.get("riskLevel")),
                    asString(raw.get("reasons")),
                    parseInstant(asString(raw.get("quarantinedAt")))
            );
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    public Result restore(String id, boolean overwrite) {
        synchronized (lock) {
            Path meta = directory.resolve(id + ".json");
            Path blob = directory.resolve(id + ".bin");
            QuarantineRecord record = read(meta);
            if (record == null) {
                return new Result(false, "Quarantine record not found: " + id, id);
            }
            Path target = Path.of(record.originalPath());
            try {
                if (Files.exists(target) && !overwrite) {
                    return new Result(false,
                            "A file already exists at the original location: " + target, id);
                }
                Path parent = target.getParent();
                if (parent != null) {
                    Files.createDirectories(parent);
                }
                Files.copy(blob, target, StandardCopyOption.REPLACE_EXISTING);
                Files.deleteIfExists(blob);
                Files.deleteIfExists(meta);
                return new Result(true, "Restored to " + target, id);
            } catch (IOException e) {
                return new Result(false, "Restore failed: " + e.getMessage(), id);
            }
        }
    }

    public Result delete(String id) {
        synchronized (lock) {
            Path meta = directory.resolve(id + ".json");
            Path blob = directory.resolve(id + ".bin");
            try {
                boolean removed = Files.deleteIfExists(blob);
                removed |= Files.deleteIfExists(meta);
                if (removed) {
                    return new Result(true, "Removed from quarantine", id);
                }
                return new Result(false, "Quarantine record not found: " + id, id);
            } catch (IOException e) {
                return new Result(false, "Delete failed: " + e.getMessage(), id);
            }
        }
    }

    /**
     * Drops quarantine items older than the configured retention window and returns how many
     * were removed.
     */
    public int purgeExpired(int retentionDays) {
        int removed = 0;
        Instant cutoff = Instant.now().minus(Math.max(1, retentionDays), ChronoUnit.DAYS);
        for (QuarantineRecord record : list()) {
            if (record.quarantinedAt() != null && record.quarantinedAt().isBefore(cutoff)) {
                if (delete(record.id()).success()) {
                    removed++;
                }
            }
        }
        return removed;
    }

    public int count() {
        synchronized (lock) {
            if (!Files.isDirectory(directory)) {
                return 0;
            }
            int count = 0;
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory, "*.bin")) {
                for (Path ignored : stream) {
                    count++;
                }
            } catch (IOException e) {
                return 0;
            }
            return count;
        }
    }

    private static String asString(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private static long asLong(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        try {
            return value == null ? 0L : Long.parseLong(String.valueOf(value));
        } catch (NumberFormatException e) {
            return 0L;
        }
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
}
