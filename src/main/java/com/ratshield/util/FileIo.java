package com.ratshield.util;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;

public final class FileIo {
    private FileIo() {
    }

    public static byte[] readHead(Path file, int maxBytes) throws IOException {
        long size = Files.size(file);
        int toRead = (int) Math.min(size, maxBytes);
        byte[] data = new byte[toRead];
        if (toRead == 0) {
            return data;
        }
        try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "r")) {
            raf.readFully(data);
        }
        return data;
    }

    public static boolean isExecutableName(String name) {
        String lower = name == null ? "" : name.toLowerCase(java.util.Locale.ROOT);
        int dot = lower.lastIndexOf('.');
        if (dot < 0) {
            return false;
        }
        String ext = lower.substring(dot + 1);
        return com.ratshield.core.FileClassifier.EXECUTABLE_EXTENSIONS.contains(ext);
    }

    public static String humanSize(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        if (bytes < 1024 * 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        }
        if (bytes < 1024L * 1024 * 1024) {
            return String.format("%.1f MB", bytes / (1024.0 * 1024));
        }
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }
}
