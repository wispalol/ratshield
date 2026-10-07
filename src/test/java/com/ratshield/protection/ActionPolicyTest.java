package com.ratshield.protection;

import com.ratshield.TestSupport;
import com.ratshield.config.AppConfig;
import com.ratshield.core.RecommendedAction;
import com.ratshield.core.ThreatVerdict;
import com.ratshield.event.SecurityEvent;
import com.ratshield.event.SecurityEventBus;
import com.ratshield.log.SecurityLogger;
import com.ratshield.quarantine.QuarantineService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ActionPolicyTest {

    @TempDir
    Path temp;

    private AppConfig config;
    private SecurityEventBus bus;
    private SecurityLogger log;
    private QuarantineService quarantine;
    private ActionPolicy policy;
    private final List<SecurityEvent> events = new CopyOnWriteArrayList<>();

    @BeforeEach
    void setUp() {
        config = AppConfig.load(temp.resolve("config.json"));
        bus = new SecurityEventBus();
        bus.subscribe(events::add);
        log = new SecurityLogger(temp.resolve("logs/security.jsonl"), 200);
        quarantine = new QuarantineService(temp.resolve("quarantine"));
        policy = new ActionPolicy(config, quarantine, bus, log);
    }

    @AfterEach
    void tearDown() {
        log.close();
    }

    private Path sample(String name) throws IOException {
        Path file = temp.resolve(name);
        Files.writeString(file, "sample content for the policy test");
        return file;
    }

    @Test
    void cleanFileIsLeftAloneAndPublishesNothing() throws IOException {
        Path file = sample("clean.txt");
        ActionPolicy.Outcome outcome = policy.apply(file, TestSupport.cleanVerdict(), "test");

        assertEquals(RecommendedAction.ALLOW, outcome.action());
        assertFalse(outcome.quarantined());
        assertTrue(Files.exists(file));
        assertTrue(events.isEmpty());
    }

    @Test
    void confirmedThreatIsQuarantinedRegardlessOfScore() throws IOException {
        Path file = sample("threat.txt");
        ThreatVerdict verdict = TestSupport.verdict("Test.Threat", 55, RecommendedAction.QUARANTINE,
                ThreatVerdict.Confidence.CONFIRMED);

        ActionPolicy.Outcome outcome = policy.apply(file, verdict, "test");

        assertTrue(outcome.quarantined(), outcome.message());
        assertFalse(Files.exists(file), "the threat file must be moved out of the way");
        assertEquals(1, quarantine.count());
        assertEquals(2, events.size(), "the verdict and the quarantine action are both reported");
        assertEquals(SecurityEvent.Type.THREAT_DETECTED, events.getFirst().type());
        assertEquals(SecurityEvent.Type.FILE_QUARANTINED, events.get(1).type());
    }

    @Test
    void heuristicScoreAboveTheThresholdIsQuarantined() throws IOException {
        Path file = sample("heuristic.txt");
        ThreatVerdict verdict = TestSupport.verdict("Heur.Suspicious.File", 80, RecommendedAction.QUARANTINE,
                ThreatVerdict.Confidence.LOW);

        ActionPolicy.Outcome outcome = policy.apply(file, verdict, "test");

        assertTrue(outcome.quarantined(), outcome.message());
        assertFalse(Files.exists(file));
    }

    @Test
    void heuristicScoreBelowTheThresholdIsNotQuarantined() throws IOException {
        Path file = sample("borderline.txt");
        ThreatVerdict verdict = TestSupport.verdict("Heur.Suspicious.File", 55, RecommendedAction.QUARANTINE,
                ThreatVerdict.Confidence.LOW);

        ActionPolicy.Outcome outcome = policy.apply(file, verdict, "test");

        assertFalse(outcome.quarantined(), "score below the configured threshold must not quarantine");
        assertTrue(Files.exists(file));
        assertEquals(1, events.size(), "the verdict is still reported to the user");
    }

    @Test
    void autoQuarantineCanBeTurnedOff() throws IOException {
        config.update(c -> c.setAutoQuarantine(false));
        Path file = sample("opt-out.txt");
        ThreatVerdict verdict = TestSupport.verdict("Test.Threat", 95, RecommendedAction.QUARANTINE,
                ThreatVerdict.Confidence.CONFIRMED);

        ActionPolicy.Outcome outcome = policy.apply(file, verdict, "test");

        assertFalse(outcome.quarantined());
        assertTrue(Files.exists(file));
        assertEquals(1, events.size());
    }

    @Test
    void failedQuarantineIsReportedNotSwallowed() throws IOException {
        Path locked = temp.resolve("locked.bin");
        Files.writeString(locked, "content");

        ThreatVerdict verdict = TestSupport.verdict("Test.Threat", 95, RecommendedAction.QUARANTINE,
                ThreatVerdict.Confidence.CONFIRMED);
        // point the quarantine directory at a path that cannot be created as a directory
        QuarantineService broken = new QuarantineService(temp.resolve("locked.bin/nested"));
        ActionPolicy brokenPolicy = new ActionPolicy(config, broken, bus, log);

        ActionPolicy.Outcome outcome = brokenPolicy.apply(locked, verdict, "test");

        assertFalse(outcome.quarantined());
        assertFalse(outcome.message().isBlank());
        assertTrue(Files.exists(locked));
        assertTrue(events.stream().anyMatch(e -> e.type() == SecurityEvent.Type.ERROR));
    }

    @Test
    void observationOnlyPublishesNoteworthyVerdicts() {
        policy.observe(TestSupport.cleanVerdict(), "process", "benign process");
        assertTrue(events.isEmpty());

        policy.observe(TestSupport.verdict("Behavior.Process.Svchost", 55, RecommendedAction.WARN,
                ThreatVerdict.Confidence.LOW), "process", "system look-alike");
        assertEquals(1, events.size());
    }
}
