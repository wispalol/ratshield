package com.ratshield.platform;

import java.time.Instant;

/**
 * Immutable view of a running process as observed by RATShield.
 *
 * @param pid          process identifier
 * @param ppid         parent process identifier
 * @param name         image name, e.g. {@code powershell.exe}
 * @param path         full path to the image when available
 * @param commandLine  command line when available
 * @param startTime    process creation time when available
 * @param user         security principal that owns the process, when available
 * @param sha256       hash of the image, lazily computed by the process monitor
 * @param signature    Authenticode status of the image, when computed
 * @param riskScore    risk score assigned by the risk engine (0 = not yet scored)
 * @param visibleWindow whether the process exposes a visible top-level window; {@code null} when unknown
 */
public record ProcessSnapshot(long pid, long ppid, String name, String path, String commandLine,
                              Instant startTime, String user, String sha256, SignatureInfo signature,
                              int riskScore, Boolean visibleWindow) {

    public ProcessSnapshot {
        name = name == null ? "" : name;
        path = path == null ? "" : path;
        commandLine = commandLine == null ? "" : commandLine;
        user = user == null ? "" : user;
        sha256 = sha256 == null ? "" : sha256;
        signature = signature == null ? SignatureInfo.unavailable("not inspected") : signature;
    }

    public static ProcessSnapshot basic(long pid, long ppid, String name) {
        return new ProcessSnapshot(pid, ppid, name, "", "", null, "", "", null, 0, null);
    }

    public ProcessSnapshot withHash(String hash) {
        return new ProcessSnapshot(pid, ppid, name, path, commandLine, startTime, user, hash, signature, riskScore,
                visibleWindow);
    }

    public ProcessSnapshot withSignature(SignatureInfo info) {
        return new ProcessSnapshot(pid, ppid, name, path, commandLine, startTime, user, sha256, info, riskScore,
                visibleWindow);
    }

    public ProcessSnapshot withRisk(int score) {
        return new ProcessSnapshot(pid, ppid, name, path, commandLine, startTime, user, sha256, signature, score,
                visibleWindow);
    }

    public ProcessSnapshot withDetails(String path, String commandLine, String user, Instant start) {
        return new ProcessSnapshot(pid, ppid, name, path == null ? "" : path, commandLine == null ? "" : commandLine,
                start, user == null ? "" : user, sha256, signature, riskScore, visibleWindow);
    }

    public ProcessSnapshot withWindow(Boolean visible) {
        return new ProcessSnapshot(pid, ppid, name, path, commandLine, startTime, user, sha256, signature, riskScore,
                visible);
    }

    public boolean isSigned() {
        return signature != null && signature.isVerified();
    }

    public String displayPath() {
        return path.isBlank() ? (commandLine.isBlank() ? name : commandLine) : path;
    }
}
