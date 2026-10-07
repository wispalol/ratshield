package com.ratshield.update;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Optional;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Applies a portable RATShield update after the running instance has exited.
 *
 * <p>Runs as its own process: waits for the parent JVM to terminate, replaces the application
 * directory with the freshly downloaded archive, then relaunches {@code RATShield.exe}. This
 * avoids the classic Windows problem of a running executable holding its own files open.</p>
 */
public final class SelfUpdater {
    private static final long WAIT_LIMIT_MS = 180_000;
    private static final long POLL_MS = 750;

    private SelfUpdater() {
    }

    public static void main(String[] args) {
        if (args.length < 3) {
            System.err.println("usage: SelfUpdater <waitPid> <appDir> <zip>");
            System.exit(2);
        }
        long waitPid = Long.parseLong(args[0]);
        Path appDir = Path.of(args[1]);
        Path zip = Path.of(args[2]);
        try {
            waitForExit(waitPid);
            int replaced = extract(zip, appDir);
            System.out.println("Replaced " + replaced + " file(s) in " + appDir);
            relaunch(appDir);
            System.exit(0);
        } catch (Exception e) {
            System.err.println("self-update failed: " + e.getMessage());
            System.exit(1);
        }
    }

    static void waitForExit(long pid) throws InterruptedException {
        long deadline = System.currentTimeMillis() + WAIT_LIMIT_MS;
        Optional<ProcessHandle> handle = ProcessHandle.of(pid);
        while (handle.isPresent() && handle.get().isAlive() && System.currentTimeMillis() < deadline) {
            Thread.sleep(POLL_MS);
            handle = ProcessHandle.of(pid);
        }
    }

    static int extract(Path zip, Path appDir) throws IOException {
        int replaced = 0;
        try (ZipInputStream in = new ZipInputStream(Files.newInputStream(zip))) {
            ZipEntry entry;
            while ((entry = in.getNextEntry()) != null) {
                if (entry.isDirectory()) {
                    continue;
                }
                Path target = safeTarget(appDir, entry.getName());
                if (target == null) {
                    continue;
                }
                Files.createDirectories(target.getParent());
                try (OutputStream out = Files.newOutputStream(target,
                        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                    in.transferTo(out);
                }
                replaced++;
            }
        }
        return replaced;
    }

    private static Path safeTarget(Path appDir, String name) {
        Path target = appDir.resolve(name).normalize();
        if (!target.startsWith(appDir.toAbsolutePath().normalize())) {
            return null;
        }
        return target;
    }

    private static void relaunch(Path appDir) {
        Path exe = appDir.resolve("RATShield.exe");
        if (!Files.isRegularFile(exe)) {
            System.err.println("release archive does not contain RATShield.exe");
            return;
        }
        try {
            new ProcessBuilder(exe.toAbsolutePath().toString())
                    .directory(appDir.toFile())
                    .start();
        } catch (IOException e) {
            System.err.println("could not relaunch RATShield: " + e.getMessage());
        }
    }
}