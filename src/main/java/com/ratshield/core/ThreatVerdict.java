package com.ratshield.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The decision produced by the detection engine for one analysed file. RATShield never
 * claims certainty from heuristics alone: {@code confidence} records how strong the
 * evidence is and {@link RiskAssessment#explain()} lists every contributing reason.
 */
public final class ThreatVerdict {
    public enum Confidence {CONFIRMED, HIGH, MEDIUM, LOW, INFORMATIONAL}

    private final String detectionName;
    private final String family;
    private final Severity severity;
    private final Confidence confidence;
    private final RiskAssessment risk;
    private final RecommendedAction action;
    private final List<String> indicators;
    private final List<String> matchedRules;

    public ThreatVerdict(String detectionName, String family, Severity severity, Confidence confidence,
                         RiskAssessment risk, RecommendedAction action, List<String> indicators,
                         List<String> matchedRules) {
        this.detectionName = detectionName;
        this.family = family == null ? "" : family;
        this.severity = severity;
        this.confidence = confidence;
        this.risk = risk;
        this.action = action;
        this.indicators = Collections.unmodifiableList(new ArrayList<>(indicators));
        this.matchedRules = Collections.unmodifiableList(new ArrayList<>(matchedRules));
    }

    public String detectionName() {
        return detectionName;
    }

    public String family() {
        return family;
    }

    public Severity severity() {
        return severity;
    }

    public Confidence confidence() {
        return confidence;
    }

    public RiskAssessment risk() {
        return risk;
    }

    public RecommendedAction action() {
        return action;
    }

    public List<String> indicators() {
        return indicators;
    }

    public List<String> matchedRules() {
        return matchedRules;
    }

    public boolean isThreat() {
        return action == RecommendedAction.QUARANTINE || action == RecommendedAction.BLOCK
                || severity == Severity.HIGH || severity == Severity.CRITICAL;
    }

    public boolean isMalicious() {
        return confidence == Confidence.CONFIRMED || (confidence == Confidence.HIGH && risk.score() >= 80);
    }

    public static ThreatVerdict clean(RiskAssessment risk) {
        return new ThreatVerdict("No.Detection", "", Severity.INFO, Confidence.INFORMATIONAL, risk,
                RecommendedAction.ALLOW, List.of(), List.of());
    }
}
