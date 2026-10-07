package com.ratshield.platform;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * Small, safe helper for invoking external Windows command line tools. Every invocation has a
 * timeout, output is bounded and a missing tool is reported as {@code unavailable} rather than
 * being treated as an error.
 */
public final class CommandRunner {
    public record Result(int exitCode, String stdout, String stderr, boolean timedOut, boolean unavailable,
                         String command) {
        public boolean ok() {
            return !timedOut && !unavailable && exitCode == 0;
        }

        public List<String> lines() {
            List<String> out = new ArrayList<>();
            for (String line : stdout.split("\r?\n")) {
                if (!line.isBlank()) {
                    out.add(line);
                }
            }
            return out;
        }
    }

    private CommandRunner() {
    }

    public static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    public static Result run(Duration timeout, String... command) {
        return run(timeout, false, command);
    }

    public static Result run(Duration timeout, boolean inheritError, String... command) {
        String display = String.join(" ", command);
        if (!isWindows() && !command[0].toLowerCase(Locale.ROOT).contains("/") && isLikelyWindowsTool(command[0])) {
            return new Result(-1, "", "", false, true, display);
        }
        Process process = null;
        try {
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.redirectErrorStream(false);
            process = builder.start();
            ByteArrayOutputStream outBuffer = new ByteArrayOutputStream();
            ByteArrayOutputStream errBuffer = new ByteArrayOutputStream();
            Thread outReader = pump(process.getInputStream(), outBuffer);
            Thread errReader = pump(process.getErrorStream(), errBuffer);
            boolean finished = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (!finished) {
                process.destroyForcibly();
                outReader.join(1000);
                errReader.join(1000);
                return new Result(-1, bounded(outBuffer), bounded(errBuffer), true, false, display);
            }
            outReader.join(2000);
            errReader.join(2000);
            return new Result(process.exitValue(), bounded(outBuffer), bounded(errBuffer), false, false, display);
        } catch (IOException e) {
            return new Result(-1, "", e.getMessage(), false, true, display);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            if (process != null) {
                process.destroyForcibly();
            }
            return new Result(-1, "", "interrupted", true, false, display);
        }
    }

    private static boolean isLikelyWindowsTool(String tool) {
        String lower = tool.toLowerCase(Locale.ROOT);
        return lower.equals("powershell") || lower.equals("powershell.exe") || lower.equals("reg")
                || lower.equals("reg.exe") || lower.equals("netstat") || lower.equals("netstat.exe")
                || lower.equals("schtasks") || lower.equals("schtasks.exe") || lower.equals("netsh")
                || lower.equals("netsh.exe") || lower.equals("taskkill") || lower.equals("taskkill.exe")
                || lower.equals("sc") || lower.equals("sc.exe") || lower.equals("icacls")
                || lower.equals("icacls.exe") || lower.equals("whoami") || lower.equals("whoami.exe");
    }

    private static Thread pump(InputStream in, ByteArrayOutputStream target) {
        Thread thread = new Thread(() -> {
            byte[] buffer = new byte[8192];
            try {
                int read;
                while ((read = in.read(buffer)) != -1) {
                    if (target.size() < 8 * 1024 * 1024) {
                        target.write(buffer, 0, read);
                    }
                }
            } catch (IOException ignored) {
                // stream closed
            }
        }, "ratshield-cmd-pump");
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    private static String bounded(ByteArrayOutputStream buffer) {
        return buffer.toString(StandardCharsets.UTF_8);
    }

    public static String powershell(String script) {
        Result result = run(Duration.ofSeconds(30), "powershell", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-Command", script);
        return result.ok() ? result.stdout().trim() : "";
    }

    public static boolean commandAvailable(String tool) {
        Result result = run(Duration.ofSeconds(8), tool, "-NoProfile", "-NonInteractive", "-Command", "exit 0");
        return !result.unavailable();
    }
}
