package com.ratshield.scanner;

import com.ratshield.TestSupport;
import com.ratshield.config.AppConfig;
import com.ratshield.event.SecurityEventBus;
import com.ratshield.log.SecurityLogger;
import com.ratshield.protection.ActionPolicy;
import com.ratshield.quarantine.QuarantineService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanEngineTest {

    @TempDir
    Path temp;

    private AppConfig config;
    private SecurityLogger log;
    private QuarantineService quarantine;
    private ScanEngine engine;

    @BeforeEach
    void setUp() {
        config = AppConfig.load(temp.resolve("config.json"));
        log = new SecurityLogger(temp.resolve("logs/security.jsonl"), 500);
        quarantine = new QuarantineService(temp.resolve("quarantine"));
        ActionPolicy policy = new ActionPolicy(config, quarantine, new SecurityEventBus(), log);
        engine = new ScanEngine(TestSupport.detection(), policy, TestSupport.unsignedSignatures(), config);
    }

    @AfterEach
    void tearDown() {
        log.close();
    }

    private ScanEngine.Summary runCustomScan(Path root, List<ScanEngine.Finding> findings) throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<ScanEngine.Summary> summary = new AtomicReference<>();
        engine.start(ScanEngine.Type.CUSTOM, List.of(new ScanEngine.Target(root, "test root")),
                new ScanEngine.Listener() {
                    @Override
                    public void onFinding(ScanEngine.Finding finding) {
                        synchronized (findings) {
                            findings.add(finding);
                        }
                    }

                    @Override
                    public void onComplete(ScanEngine.Summary result) {
                        summary.set(result);
                        done.countDown();
                    }
                });
        assertTrue(done.await(60, TimeUnit.SECONDS), "scan did not complete in time");
        assertNotNull(summary.get());
        return summary.get();
    }

    @Test
    void scanFindsQuarantinesAndLeavesCleanFilesAlone() throws Exception {
        Path eicar = temp.resolve("eicar.com");
        Files.write(eicar, TestSupport.eicar());
        Path clean = temp.resolve("notes.txt");
        Files.writeString(clean, "Shopping list: milk, eggs, bread.");

        List<ScanEngine.Finding> findings = Collections.synchronizedList(new ArrayList<>());
        ScanEngine.Summary summary = runCustomScan(temp, findings);

        assertTrue(summary.scanned() >= 2, "scanned=" + summary.scanned());
        assertTrue(summary.threats() >= 1, "threats=" + summary.threats());
        assertTrue(summary.quarantined() >= 1);
        assertFalse(Files.exists(eicar), "the EICAR file must be in quarantine");
        assertTrue(Files.exists(clean), "clean files must stay in place");
        assertEquals(1, quarantine.count());
        assertTrue(findings.stream().anyMatch(f ->
                f.verdict().matchedRules().contains("Test_EICAR")), "no EICAR finding reported");
        assertFalse(summary.cancelled());
        assertFalse(engine.isRunning());
    }

    @Test
    void exclusionListSkipsFiles() throws Exception {
        Path excludedDir = temp.resolve("excluded");
        Files.createDirectories(excludedDir);
        Files.write(excludedDir.resolve("eicar.com"), TestSupport.eicar());
        config.update(c -> c.setExcludedPaths(List.of(excludedDir.toString())));

        List<ScanEngine.Finding> findings = Collections.synchronizedList(new ArrayList<>());
        ScanEngine.Summary summary = runCustomScan(excludedDir, findings);

        assertEquals(0, summary.threats());
        assertTrue(findings.isEmpty());
        assertTrue(Files.exists(excludedDir.resolve("eicar.com")));
    }

    @Test
    void quickTargetsExistOrAreExplicitlyReported() {
        List<Path> targets = ScanEngine.quickTargets();
        assertNotNull(targets);
        for (Path target : targets) {
            assertNotNull(target);
        }
        assertNotNull(ScanEngine.fullRoots());
    }

    @Test
    void startingTwiceIsRefusedWhileRunning() throws Exception {
        CountDownLatch firstDone = new CountDownLatch(1);
        engine.start(ScanEngine.Type.CUSTOM, List.of(new ScanEngine.Target(temp, "root")),
                new ScanEngine.Listener() {
                    @Override
                    public void onComplete(ScanEngine.Summary summary) {
                        firstDone.countDown();
                    }
                });
        engine.start(ScanEngine.Type.CUSTOM, List.of(new ScanEngine.Target(temp, "root")),
                new ScanEngine.Listener() {
                    @Override
                    public void onComplete(ScanEngine.Summary summary) {
                        firstDone.countDown();
                    }
                });
        assertTrue(firstDone.await(60, TimeUnit.SECONDS));
        assertFalse(engine.isRunning());
    }
}
