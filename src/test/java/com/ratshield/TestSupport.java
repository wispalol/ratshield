package com.ratshield;

import com.ratshield.core.DetectionEngine;
import com.ratshield.core.RecommendedAction;
import com.ratshield.core.ReputationService;
import com.ratshield.core.RiskAssessment;
import com.ratshield.core.RiskEngine;
import com.ratshield.core.RiskReason;
import com.ratshield.core.Severity;
import com.ratshield.core.ThreatVerdict;
import com.ratshield.core.rules.RuleEngine;
import com.ratshield.platform.SignatureInfo;
import com.ratshield.platform.SignatureProvider;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

/**
 * Shared fixtures: the EICAR standard test file (the only "malware" RATShield ever touches),
 * stub signature providers and the detection stack the tests drive.
 */
public final class TestSupport {
    public static final String EICAR =
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    public static final String EICAR_SHA256 =
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    private TestSupport() {
    }

    public static byte[] eicar() {
        return EICAR.getBytes(StandardCharsets.US_ASCII);
    }

    public static SignatureProvider unsignedSignatures() {
        return file -> SignatureInfo.unsigned();
    }

    public static SignatureProvider unavailableSignatures() {
        return file -> SignatureInfo.unavailable("not inspected by tests");
    }

    public static RuleEngine rules() {
        return RuleEngine.loadDefaults();
    }

    public static DetectionEngine detection() {
        return new DetectionEngine(rules(),
                new ReputationService(ReputationService.RemoteConfig.disabled()),
                unsignedSignatures(), new RiskEngine());
    }

    public static ThreatVerdict verdict(String detection, int score, RecommendedAction action,
                                        ThreatVerdict.Confidence confidence) {
        RiskAssessment risk = new RiskAssessment(score,
                List.of(new RiskReason("rule.Sample", "Detection rule matched: " + detection, 55)),
                action, confidence.name());
        return new ThreatVerdict(detection, "Test", Severity.fromScore(score), confidence, risk,
                action, List.of("detection rule matched"), List.of("Sample_Rule"));
    }

    public static ThreatVerdict cleanVerdict() {
        return ThreatVerdict.clean(new RiskAssessment(0, List.of(), RecommendedAction.ALLOW, "LOW"));
    }
}
