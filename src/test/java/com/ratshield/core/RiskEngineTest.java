package com.ratshield.core;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RiskEngineTest {
    private final RiskEngine engine = new RiskEngine();

    @Test
    void emptyEvidenceIsClean() {
        RiskAssessment risk = engine.assess(List.of());
        assertEquals(0, risk.score());
        assertEquals(RecommendedAction.ALLOW, risk.action());
        assertEquals(RiskLevel.SAFE, risk.level());
        assertEquals("LOW", risk.confidence());
    }

    @Test
    void confirmedRuleEvidenceForcesQuarantine() {
        RiskAssessment risk = engine.assess(List.of(
                new RiskFactor("rule.Test_EICAR", "Detection rule matched: Test_EICAR", 55, Severity.CRITICAL)));
        assertEquals(55, risk.score());
        assertEquals(RecommendedAction.QUARANTINE, risk.action());
        assertEquals("CONFIRMED", risk.confidence());
    }

    @Test
    void reputationEvidenceIsConfirmed() {
        RiskAssessment risk = engine.assess(List.of(
                new RiskFactor("reputation.known_bad", "Known threat in reputation database", 60, Severity.CRITICAL)));
        assertEquals("CONFIRMED", risk.confidence());
        assertEquals(RecommendedAction.QUARANTINE, risk.action());
    }

    @Test
    void heuristicScoreFollowsConfiguredThresholds() {
        assertEquals(RecommendedAction.WARN,
                engine.assess(List.of(new RiskFactor("location.temp", "temporary", 45, Severity.MEDIUM))).action());
        assertEquals(RecommendedAction.ALLOW,
                engine.assess(List.of(new RiskFactor("location.temp", "temporary", 25, Severity.LOW))).action());
        assertEquals(RecommendedAction.QUARANTINE,
                engine.assess(List.of(new RiskFactor("location.temp", "temporary", 85, Severity.CRITICAL))).action());
    }

    @Test
    void weakIndicatorsEarnASynergyBonus() {
        RiskAssessment risk = engine.assess(List.of(
                new RiskFactor("pe.unsigned", "Unsigned executable", 15, Severity.MEDIUM),
                new RiskFactor("recent.download", "Recently downloaded", 12, Severity.MEDIUM),
                new RiskFactor("location.temp", "Temporary directory", 10, Severity.MEDIUM)));
        assertEquals(15 + 12 + 10 + 12, risk.score());
        assertTrue(risk.reasons().stream().anyMatch(r -> r.code().equals("synergy.combination")));
    }

    @Test
    void duplicateCodesAreMergedNotDoubleCounted() {
        RiskAssessment risk = engine.assess(List.of(
                new RiskFactor("location.temp", "first", 10, Severity.MEDIUM),
                new RiskFactor("location.temp", "second", 10, Severity.MEDIUM)));
        assertEquals(10, risk.score());
    }

    @Test
    void validSignatureCapsHeuristicScore() {
        RiskAssessment risk = engine.assess(List.of(
                new RiskFactor("signature.valid", "Signed by Example", -15, Severity.INFO),
                new RiskFactor("extension.double", "Deceptive double extension", 20, Severity.HIGH),
                new RiskFactor("extension.rtl", "Right-to-left override", 25, Severity.HIGH),
                new RiskFactor("string.indicators", "Embedded strings", 20, Severity.MEDIUM),
                new RiskFactor("location.temp", "Temporary directory", 10, Severity.MEDIUM),
                new RiskFactor("recent.download", "Recently downloaded", 12, Severity.MEDIUM)));
        assertEquals(55, risk.score());
        assertTrue(risk.reasons().stream().anyMatch(r -> r.code().equals("signature.cap")));
    }

    @Test
    void explainListsEveryContribution() {
        RiskAssessment risk = engine.assess(List.of(
                new RiskFactor("rule.Sample", "Detection rule matched", 55, Severity.CRITICAL)));
        String text = risk.explain();
        assertTrue(text.contains("55"));
        assertTrue(text.contains("Detection rule matched"));
        assertTrue(text.contains("QUARANTINE"));
    }
}
