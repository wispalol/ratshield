package com.ratshield.event;

import com.ratshield.core.ThreatVerdict;

import java.time.Instant;
import java.util.Objects;

/**
 * A single thing that happened which the user should be able to see: a detection, a quarantine
 * action, a scan finishing, or a protection state change.
 */
public record SecurityEvent(
        Type type,
        Instant timestamp,
        String title,
        String message,
        ThreatVerdict verdict,
        Severity severity
) {
    public enum Type {
        THREAT_DETECTED,
        FILE_QUARANTINED,
        FILE_BLOCKED,
        SCAN_STARTED,
        SCAN_COMPLETED,
        SHIELD_TOGGLED,
        CONFIG_CHANGED,
        QUARANTINE_RESTORED,
        QUARANTINE_DELETED,
        SYSTEM_INFO,
        UPDATE_AVAILABLE,
        UPDATE_STARTED,
        UPDATE_FAILED,
        ERROR
    }

    public enum Severity {
        INFO,
        WARNING,
        CRITICAL
    }

    public SecurityEvent {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(timestamp, "timestamp");
        if (title == null || title.isBlank()) {
            throw new IllegalArgumentException("title must not be blank");
        }
        message = message == null ? "" : message;
        severity = severity == null ? Severity.INFO : severity;
    }

    public static SecurityEvent of(Type type, Severity severity, String title, String message) {
        return new SecurityEvent(type, Instant.now(), title, message, null, severity);
    }

    public static SecurityEvent threat(ThreatVerdict verdict) {
        Severity severity = switch (verdict.severity()) {
            case CRITICAL, HIGH -> Severity.CRITICAL;
            case MEDIUM, LOW -> Severity.WARNING;
            case INFO -> Severity.INFO;
        };
        String title = switch (verdict.action()) {
            case QUARANTINE, BLOCK -> "Threat detected";
            case WARN -> "Suspicious activity";
            case ALLOW -> "Scan result";
        };
        String message = verdict.detectionName() + ": " + verdict.risk().explain();
        return new SecurityEvent(Type.THREAT_DETECTED, Instant.now(), title, message, verdict, severity);
    }
}
