package com.ratshield.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class RiskAssessment {
    private final int score;
    private final RiskLevel level;
    private final RecommendedAction action;
    private final List<RiskReason> reasons;
    private final String confidence;

    public RiskAssessment(int score, List<RiskReason> reasons, RecommendedAction action, String confidence) {
        this.score = Math.clamp(score, 0, 100);
        this.level = RiskLevel.fromScore(this.score);
        this.reasons = Collections.unmodifiableList(new ArrayList<>(reasons));
        this.action = action;
        this.confidence = confidence;
    }

    public int score() {
        return score;
    }

    public RiskLevel level() {
        return level;
    }

    public RecommendedAction action() {
        return action;
    }

    public List<RiskReason> reasons() {
        return reasons;
    }

    public String confidence() {
        return confidence;
    }

    public String explain() {
        StringBuilder sb = new StringBuilder();
        sb.append(level).append(" RISK — ").append(score).append("/100").append(System.lineSeparator());
        for (RiskReason r : reasons) {
            String sign = r.points() >= 0 ? "+" : "";
            sb.append(sign).append(r.points()).append(' ').append(r.label()).append(System.lineSeparator());
        }
        sb.append("Recommended action: ").append(action);
        return sb.toString();
    }

    @Override
    public String toString() {
        return explain();
    }
}
