package com.ratshield.protection;

import com.ratshield.config.AppConfig;
import com.ratshield.core.RecommendedAction;
import com.ratshield.core.ThreatVerdict;
import com.ratshield.event.SecurityEvent;
import com.ratshield.event.SecurityEventBus;
import com.ratshield.log.SecurityLogger;
import com.ratshield.quarantine.QuarantineService;

import java.nio.file.Path;
import java.time.Instant;

/**
 * Single place where a verdict becomes an action.
 *
 * <p>The scan engine and the real-time monitors must not be able to disagree about what
 * happens to a file, so both route their verdicts through this class. It applies the configured
 * thresholds, performs the quarantine itself, logs the outcome and publishes the corresponding
 * events — including a failure event when quarantine did not work, because silently swallowing
 * a failed containment is worse than doing nothing.</p>
 */
public final class ActionPolicy {
    public record Outcome(RecommendedAction action, boolean quarantined, String message) {
    }

    private final AppConfig config;
    private final QuarantineService quarantine;
    private final SecurityEventBus bus;
    private final SecurityLogger log;

    public ActionPolicy(AppConfig config, QuarantineService quarantine, SecurityEventBus bus,
                        SecurityLogger log) {
        this.config = config;
        this.quarantine = quarantine;
        this.bus = bus;
        this.log = log;
    }

    /**
     * Publishes and logs a verdict that has no file to act on (running processes, connections,
     * auto-start entries). The actual containment for those is a user decision in the UI.
     */
    public void observe(ThreatVerdict verdict, String source, String detail) {
        if (verdict == null) {
            return;
        }
        int score = verdict.risk().score();
        if (verdict.action() == RecommendedAction.ALLOW && score < config.getWarnScore()) {
            return;
        }
        bus.publish(SecurityEvent.threat(verdict));
        log.warn(source, detail + " — score " + score + "/100: " + verdict.risk().explain());
    }

    public Outcome apply(Path path, ThreatVerdict verdict, String source) {
        if (verdict == null) {
            return new Outcome(RecommendedAction.ALLOW, false, "no verdict");
        }
        int score = verdict.risk().score();
        RecommendedAction action = verdict.action();

        if (action == RecommendedAction.ALLOW && score < config.getWarnScore()) {
            return new Outcome(action, false, "clean");
        }
        bus.publish(SecurityEvent.threat(verdict));

        // A rule or reputation hit is confirmed evidence: thresholds exist to decide what to do
        // with *heuristic* score, not with a matching signature.
        boolean confirmed = verdict.confidence() == ThreatVerdict.Confidence.CONFIRMED;
        boolean overQuarantineLine = action == RecommendedAction.QUARANTINE
                && (confirmed || score >= config.getAutoQuarantineScore());
        if (overQuarantineLine && config.isAutoQuarantine()) {
            QuarantineService.Result result = quarantine.quarantine(path, verdict);
            if (result.success()) {
                log.warn("quarantine", source + ": " + result.message());
                bus.publish(new SecurityEvent(SecurityEvent.Type.FILE_QUARANTINED, Instant.now(),
                        "Moved to quarantine", path + " — " + verdict.detectionName()
                                + " (" + score + "/100)", verdict, SecurityEvent.Severity.CRITICAL));
                return new Outcome(action, true, result.message());
            }
            log.error("quarantine", source + " could not quarantine " + path + ": " + result.message());
            bus.publish(new SecurityEvent(SecurityEvent.Type.ERROR, Instant.now(), "Quarantine failed",
                    path + " — " + result.message(), verdict, SecurityEvent.Severity.CRITICAL));
            return new Outcome(action, false, result.message());
        }

        if (action == RecommendedAction.WARN || score >= config.getWarnScore()) {
            log.warn("protection", source + ": " + path + " scored " + score + "/100 — "
                    + verdict.risk().explain());
        }
        return new Outcome(action, false, verdict.risk().explain());
    }

    public int warnScore() {
        return config.getWarnScore();
    }

    public int quarantineScore() {
        return config.getAutoQuarantineScore();
    }
}
