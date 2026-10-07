package com.ratshield.core;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Transparent risk scoring. Every point added to the score is reported as a
 * {@link RiskReason} so the UI can always explain why a verdict was reached.
 *
 * <p>Combining weak indicators is deliberate: several individually minor signals
 * (unsigned, downloaded, temporary folder, persistence attempt) escalate the score far more
 * than any single one of them.</p>
 */
public final class RiskEngine {
    public static final int CONFIRM_THRESHOLD = 80;
    public static final int QUARANTINE_THRESHOLD = 60;
    public static final int WARN_THRESHOLD = 40;
    public static final int LOW_THRESHOLD = 20;

    private final int quarantineThreshold;
    private final int warnThreshold;

    public RiskEngine() {
        this(QUARANTINE_THRESHOLD, WARN_THRESHOLD);
    }

    public RiskEngine(int quarantineThreshold, int warnThreshold) {
        this.quarantineThreshold = quarantineThreshold;
        this.warnThreshold = warnThreshold;
    }

    public RiskAssessment assess(List<RiskFactor> factors) {
        List<RiskReason> reasons = new ArrayList<>();
        int raw = 0;
        Set<String> codes = new HashSet<>();
        boolean confirmedEvidence = false;
        for (RiskFactor factor : factors) {
            if (factor == null || factor.points() == 0) {
                continue;
            }
            if (codes.add(factor.code())) {
                raw += factor.points();
                reasons.add(new RiskReason(factor.code(), factor.label(), factor.points()));
            } else {
                for (int i = 0; i < reasons.size(); i++) {
                    if (reasons.get(i).code().equals(factor.code())) {
                        RiskReason existing = reasons.get(i);
                        if (factor.points() > existing.points()) {
                            reasons.set(i, new RiskReason(existing.code(), factor.label(), factor.points()));
                        }
                        break;
                    }
                }
            }
            if (factor.code().startsWith("reputation.") || factor.code().startsWith("rule.")
                    || factor.code().startsWith("archive.bomb")) {
                confirmedEvidence = true;
            }
        }

        int synergy = synergyBonus(codes);
        if (synergy > 0) {
            raw += synergy;
            reasons.add(new RiskReason("synergy.combination",
                    "Combined indicator: " + synergyDescription(codes), synergy));
        }

        Set<String> behaviours = new HashSet<>();
        for (RiskFactor f : factors) {
            if (f != null && f.code().startsWith("behaviour.")) {
                behaviours.add(f.code());
            }
        }
        int categories = 0;
        if (hasCode(codes, "rule.") || hasCode(codes, "reputation.")) {
            categories++;
        }
        if (hasCode(codes, "pe.") || hasCode(codes, "type.") || hasCode(codes, "extension.")
                || hasCode(codes, "entropy.")) {
            categories++;
        }
        if (hasCode(codes, "location.") || hasCode(codes, "recent.")) {
            categories++;
        }
        if (!behaviours.isEmpty()) {
            categories++;
        }
        if (hasCode(codes, "signature.")) {
            categories++;
        }

        boolean signedClean = codes.contains("signature.valid") && !confirmedEvidence;
        int score = Math.clamp(raw, 0, 100);
        if (signedClean && score > 55) {
            score = 55;
            reasons.add(new RiskReason("signature.cap",
                    "Score capped: file carries a valid code-signature", 0));
        }

        String confidence;
        if (confirmedEvidence) {
            confidence = "CONFIRMED";
        } else if (score >= 60 && categories >= 4) {
            confidence = "HIGH";
        } else if (categories >= 3 && score >= WARN_THRESHOLD) {
            confidence = "MEDIUM";
        } else {
            confidence = "LOW";
        }

        RecommendedAction action;
        if (confirmedEvidence || score >= quarantineThreshold) {
            action = RecommendedAction.QUARANTINE;
        } else if (score >= warnThreshold) {
            action = RecommendedAction.WARN;
        } else if (score >= LOW_THRESHOLD) {
            action = RecommendedAction.ALLOW;
        } else {
            action = RecommendedAction.ALLOW;
        }

        reasons.sort(Comparator.comparingInt((RiskReason r) -> r.points()).reversed());
        return new RiskAssessment(score, reasons, action, confidence);
    }

    private static boolean hasCode(Set<String> codes, String prefix) {
        for (String code : codes) {
            if (code.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static int synergyBonus(Set<String> codes) {
        int bonus = 0;
        boolean unsigned = codes.contains("pe.unsigned");
        boolean downloaded = codes.contains("recent.download");
        boolean temp = codes.contains("location.temp") || codes.contains("location.appdata");
        boolean persistence = codes.contains("behaviour.persistence_created");
        boolean injection = codes.contains("behaviour.process_injection");
        boolean credential = codes.contains("behaviour.credential_access");
        boolean connection = codes.contains("behaviour.suspicious_connection");
        boolean shell = codes.contains("behaviour.spawned_shell");
        boolean defense = codes.contains("behaviour.defense_evasion");

        if (unsigned && downloaded && temp) {
            bonus += 12;
        }
        if (unsigned && persistence) {
            bonus += 10;
        }
        if (unsigned && injection) {
            bonus += 12;
        }
        if (unsigned && credential) {
            bonus += 8;
        }
        if (persistence && connection) {
            bonus += 8;
        }
        if (shell && persistence) {
            bonus += 8;
        }
        if (defense && unsigned) {
            bonus += 8;
        }
        return Math.min(bonus, 30);
    }

    private static String synergyDescription(Set<String> codes) {
        List<String> parts = new ArrayList<>();
        if (codes.contains("pe.unsigned")) {
            parts.add("unsigned");
        }
        if (codes.contains("recent.download")) {
            parts.add("recently downloaded");
        }
        if (codes.contains("location.temp") || codes.contains("location.appdata")) {
            parts.add("user-writable location");
        }
        if (codes.contains("behaviour.persistence_created")) {
            parts.add("creates persistence");
        }
        if (codes.contains("behaviour.spawned_shell")) {
            parts.add("spawns a shell");
        }
        if (codes.contains("behaviour.suspicious_connection")) {
            parts.add("opens a suspicious connection");
        }
        if (codes.contains("behaviour.process_injection")) {
            parts.add("injects into other processes");
        }
        if (codes.contains("behaviour.credential_access")) {
            parts.add("touches credential stores");
        }
        if (parts.isEmpty()) {
            return "multiple weak indicators";
        }
        return String.join(" + ", parts);
    }
}
