package com.ratshield.core;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Safe archive inspection. Archives are never extracted to disk and never executed.
 * Hard limits protect against archive bombs (entry count, uncompressed volume,
 * compression ratio and nesting depth).
 */
public final class ArchiveAnalyzer {
    public static final int MAX_ENTRIES = 2000;
    public static final long MAX_TOTAL_UNCOMPRESSED = 512L * 1024 * 1024;
    public static final long MAX_ENTRY_UNCOMPRESSED = 128L * 1024 * 1024;
    public static final int MAX_COMPRESSION_RATIO = 200;
    public static final int MAX_DEPTH = 3;

    public record Sample(String entryName, long size, long compressedSize, byte[] data, boolean truncated, Path archive) {
    }

    public record Finding(String entryName, String reason, Severity severity) {
    }

    public record Report(int entries, long totalUncompressed, double maxRatio, boolean bombSuspected,
                         List<Sample> executableSamples, List<Finding> findings, List<String> errors,
                         boolean supported) {
    }

    public Report inspect(Path archive, int depth) {
        int entries = 0;
        long total = 0;
        double maxRatio = 0;
        boolean bomb = false;
        List<Sample> samples = new ArrayList<>();
        List<Finding> findings = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        boolean supported = true;

        String name = archive.getFileName() == null ? "" : archive.getFileName().toString().toLowerCase(Locale.ROOT);
        if (name.endsWith(".zip") || name.endsWith(".jar") || name.endsWith(".apk") || name.endsWith(".docx")
                || name.endsWith(".xlsx") || name.endsWith(".pptx") || name.endsWith(".msix")) {
            try (InputStream raw = java.nio.file.Files.newInputStream(archive);
                 ZipInputStream zip = new ZipInputStream(raw)) {
                ZipEntry entry;
                byte[] buffer = new byte[64 * 1024];
                while ((entry = zip.getNextEntry()) != null) {
                    entries++;
                    if (entries > MAX_ENTRIES) {
                        findings.add(new Finding("<archive>", "Entry count limit exceeded (" + MAX_ENTRIES + ")", Severity.MEDIUM));
                        bomb = true;
                        break;
                    }
                    if (entry.isDirectory()) {
                        zip.closeEntry();
                        continue;
                    }
                    long declared = entry.getSize();
                    long compressed = entry.getCompressedSize();
                    long readTotal = 0;
                    byte[] head = null;
                    int headLen = 0;
                    byte[] headBuffer = new byte[8192];
                    int n;
                    boolean truncated = false;
                    while ((n = zip.read(buffer)) > 0) {
                        if (headLen < headBuffer.length) {
                            int copy = Math.min(n, headBuffer.length - headLen);
                            System.arraycopy(buffer, 0, headBuffer, headLen, copy);
                            headLen += copy;
                        }
                        readTotal += n;
                        if (readTotal > MAX_ENTRY_UNCOMPRESSED) {
                            truncated = true;
                            findings.add(new Finding(entry.getName(),
                                    "Entry exceeds maximum decompressed size", Severity.MEDIUM));
                            bomb = true;
                            break;
                        }
                    }
                    if (readTotal > 0) {
                        total += readTotal;
                    }
                    if (total > MAX_TOTAL_UNCOMPRESSED) {
                        findings.add(new Finding(entry.getName(),
                                "Archive exceeds maximum decompressed volume", Severity.HIGH));
                        bomb = true;
                        zip.closeEntry();
                        break;
                    }
                    if (compressed > 0) {
                        double ratio = (double) readTotal / compressed;
                        if (ratio > maxRatio) {
                            maxRatio = ratio;
                        }
                        if (ratio > MAX_COMPRESSION_RATIO && readTotal > 1024 * 1024) {
                            findings.add(new Finding(entry.getName(),
                                    String.format("Suspicious compression ratio %.0f:1", ratio), Severity.HIGH));
                            bomb = true;
                        }
                    } else if (declared > 0) {
                        double ratio = (double) readTotal / Math.max(1L, entry.getCompressedSize() == -1 ? readTotal : entry.getCompressedSize());
                        if (ratio > maxRatio) {
                            maxRatio = ratio;
                        }
                    }
                    if (headLen > 0) {
                        head = new byte[headLen];
                        System.arraycopy(headBuffer, 0, head, 0, headLen);
                    }
                    String entryName = entry.getName();
                    FileClassifier.Classification c = FileClassifier.classify(entryName, head);
                    boolean entryExecutable = FileClassifier.isExecutableLike(c);
                    boolean deceptive = c.doubleExtension() || c.rightToLeftOverride();
                    if (entryExecutable && deceptive) {
                        findings.add(new Finding(entryName,
                                "Deceptive double extension inside archive", Severity.HIGH));
                    }
                    if (entryExecutable && head != null && head.length >= 2 && head[0] == 'M' && head[1] == 'Z'
                            && !entryName.toLowerCase(Locale.ROOT).endsWith(".exe")) {
                        findings.add(new Finding(entryName,
                                "Executable content with a non-executable extension", Severity.HIGH));
                    }
                    if (entryExecutable && entryName.toLowerCase(Locale.ROOT).contains("autorun")
                            || entryName.toLowerCase(Locale.ROOT).endsWith("setup.exe")) {
                        findings.add(new Finding(entryName, "Auto-start style payload inside archive", Severity.MEDIUM));
                    }
                    if (entryExecutable && samples.size() < 24) {
                        samples.add(new Sample(entryName, readTotal, compressed, head, truncated, archive));
                    }
                    if (entryExecutable && FileClassifier.looksLikeArchiveName(entryName) && depth < MAX_DEPTH) {
                        findings.add(new Finding(entryName, "Nested archive detected", Severity.LOW));
                    }
                    zip.closeEntry();
                }
            } catch (IOException | RuntimeException e) {
                errors.add("archive read error: " + e.getMessage());
                supported = false;
            }
        } else if (name.endsWith(".gz") || name.endsWith(".tgz")) {
            try (InputStream raw = java.nio.file.Files.newInputStream(archive);
                 GZIPInputStream gzip = new GZIPInputStream(raw)) {
                byte[] buffer = new byte[64 * 1024];
                long readTotal = 0;
                byte[] head = new byte[8192];
                int headLen = 0;
                int n;
                while ((n = gzip.read(buffer)) > 0 && readTotal <= MAX_ENTRY_UNCOMPRESSED) {
                    if (headLen < head.length) {
                        int copy = Math.min(n, head.length - headLen);
                        System.arraycopy(buffer, 0, head, headLen, copy);
                        headLen += copy;
                    }
                    readTotal += n;
                }
                entries = 1;
                total = readTotal;
                if (readTotal > 1024 * 1024) {
                    maxRatio = 10;
                    if (readTotal > MAX_ENTRY_UNCOMPRESSED / 4) {
                        findings.add(new Finding(archive.getFileName().toString(),
                                "Large gzip stream", Severity.LOW));
                    }
                }
                byte[] headTrim = new byte[headLen];
                System.arraycopy(head, 0, headTrim, 0, headLen);
                if (headLen >= 2 && headTrim[0] == 'P' && headTrim[1] == 'K') {
                    findings.add(new Finding(archive.getFileName().toString(),
                            "Compressed stream contains another archive", Severity.LOW));
                }
            } catch (IOException | RuntimeException e) {
                errors.add("gzip read error: " + e.getMessage());
                supported = false;
            }
        } else if (name.endsWith(".7z") || name.endsWith(".rar") || name.endsWith(".iso") || name.endsWith(".cab")) {
            supported = false;
            findings.add(new Finding(archive.getFileName().toString(),
                    "Format cannot be inspected in-process; quarantining is advised for suspicious sources",
                    Severity.LOW));
        } else {
            supported = false;
        }

        return new Report(entries, total, maxRatio, bomb, samples, findings, errors, supported);
    }
}
