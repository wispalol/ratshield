package com.ratshield.protection;

import com.ratshield.TestSupport;
import com.ratshield.core.RecommendedAction;
import com.ratshield.core.RiskEngine;
import com.ratshield.core.ThreatVerdict;
import com.ratshield.platform.NetworkConnection;
import com.ratshield.platform.ProcessSnapshot;
import com.ratshield.platform.SignatureInfo;
import com.ratshield.platform.WindowsPersistenceProvider.EntryType;
import com.ratshield.platform.WindowsPersistenceProvider.PersistenceEntry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BehaviorAnalyzerTest {

    private final BehaviorAnalyzer analyzer =
            new BehaviorAnalyzer(new RiskEngine(), TestSupport.unavailableSignatures());

    @TempDir
    Path temp;

    private ProcessSnapshot snapshot(long pid, String name, Path file, String commandLine)
            throws IOException {
        Files.createDirectories(file.getParent());
        Files.writeString(file, "placeholder");
        return ProcessSnapshot.basic(pid, 1, name).withDetails(file.toString(), commandLine, "user", Instant.now());
    }

    @Test
    void systemProcessNameRunningFromTempIsFlagged() throws IOException {
        ProcessSnapshot process = snapshot(4242, "svchost.exe", temp.resolve("svchost.exe"), "");

        ThreatVerdict verdict = analyzer.analyseProcess(process, Map.of());

        assertNotNull(verdict);
        assertTrue(verdict.risk().score() >= 40, verdict.risk().explain());
        assertEquals(RecommendedAction.WARN, verdict.action());
        assertTrue(verdict.detectionName().startsWith("Behavior.Process."));
        assertTrue(verdict.indicators().contains("system process look-alike"), verdict.indicators().toString());
        assertTrue(verdict.indicators().contains("temporary folder"));
    }

    @Test
    void normalSystemProcessProducesNoVerdict() {
        String windir = System.getenv("SystemRoot");
        String base = windir == null || windir.isBlank() ? "C:\\Windows" : windir;
        ProcessSnapshot process = ProcessSnapshot.basic(4, 0, "notepad.exe")
                .withDetails(base + "\\System32\\notepad.exe", "", "user", Instant.now());

        assertNull(analyzer.analyseProcess(process, Map.of()));
    }

    @Test
    void encodedCommandLineIsEscalated() throws IOException {
        ProcessSnapshot process = snapshot(777, "update.exe", temp.resolve("update.exe"),
                "powershell.exe -nop -w hidden -EncodedCommand SQBFAFgA");

        ThreatVerdict verdict = analyzer.analyseProcess(process, Map.of());

        assertNotNull(verdict);
        assertTrue(verdict.risk().score() >= 30, verdict.risk().explain());
        assertTrue(verdict.indicators().contains("obfuscated command line"), verdict.indicators().toString());
        assertTrue(verdict.risk().reasons().stream()
                .anyMatch(r -> r.code().equals("behaviour.defense_evasion")));
    }

    @Test
    void scriptHostWithoutMaliciousContextStaysLowRisk() {
        String windir = System.getenv("SystemRoot");
        String base = windir == null || windir.isBlank() ? "C:\\Windows" : windir;
        ProcessSnapshot powershell = ProcessSnapshot.basic(9, 1, "powershell.exe")
                .withDetails(base + "\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "-ExecutionPolicy Bypass -File C:\\Scripts\\job.ps1", "user", Instant.now());

        ThreatVerdict verdict = analyzer.analyseProcess(powershell, Map.of());

        assertNotNull(verdict);
        assertTrue(verdict.risk().score() < RiskEngine.QUARANTINE_THRESHOLD, verdict.risk().explain());
        assertEquals(RecommendedAction.ALLOW, verdict.action());
    }

    @Test
    void unsignedProcessTalkingToTheInternetIsReported() throws IOException {
        ProcessSnapshot owner = ProcessSnapshot.basic(31337, 1, "helper.exe")
                .withSignature(SignatureInfo.unsigned());
        owner = owner.withDetails(temp.resolve("helper.exe").toString(), "", "user", Instant.now());
        Files.writeString(temp.resolve("helper.exe"), "placeholder");
        NetworkConnection connection = new NetworkConnection(31337, "tcp", "10.0.0.5", 51234,
                "203.0.113.9", 4444, "ESTABLISHED", "", Instant.now());

        ThreatVerdict verdict = analyzer.analyseNetwork(connection, owner);

        assertNotNull(verdict);
        assertTrue(verdict.risk().reasons().stream()
                .anyMatch(r -> r.code().equals("behaviour.suspicious_connection")),
                verdict.risk().explain());
    }

    @Test
    void listenerFromAppDataIsReported() {
        ProcessSnapshot owner = ProcessSnapshot.basic(88, 1, "agent.exe")
                .withSignature(SignatureInfo.unsigned());
        owner = owner.withDetails("C:\\Users\\user\\AppData\\Roaming\\agent.exe", "", "user", Instant.now());
        NetworkConnection connection = new NetworkConnection(88, "tcp", "0.0.0.0", 9001,
                "*", 0, "LISTEN", "", Instant.now());

        ThreatVerdict verdict = analyzer.analyseNetwork(connection, owner);

        assertNotNull(verdict);
        assertTrue(verdict.risk().score() >= 30, verdict.risk().explain());
        assertTrue(verdict.indicators().stream().anyMatch(i -> i.contains("listening")),
                verdict.indicators().toString());
    }

    @Test
    void encodedRunKeyEntryIsEscalated() {
        PersistenceEntry entry = new PersistenceEntry("run-updater", EntryType.REGISTRY_RUN, "Updater",
                "powershell.exe -enc SQBFAFgAQUJDR",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "", "test");

        ThreatVerdict verdict = analyzer.analysePersistence(entry);

        assertNotNull(verdict);
        assertTrue(verdict.risk().score() >= 40, verdict.risk().explain());
        assertTrue(verdict.indicators().contains("encoded command"), verdict.indicators().toString());
        assertTrue(verdict.risk().reasons().stream()
                .anyMatch(r -> r.code().equals("behaviour.persistence_created")));
    }

    @Test
    void systemServiceEntryStaysBelowTheWarnLine() {
        String windir = System.getenv("SystemRoot");
        String base = windir == null || windir.isBlank() ? "C:\\Windows" : windir;
        PersistenceEntry entry = new PersistenceEntry("svc-spooler", EntryType.SERVICE, "Spooler",
                base + "\\System32\\spoolsv.exe", "Local System", "Microsoft", "test");

        ThreatVerdict verdict = analyzer.analysePersistence(entry);

        assertNotNull(verdict);
        assertEquals(RecommendedAction.ALLOW, verdict.action(), verdict.risk().explain());
        assertTrue(verdict.risk().score() < RiskEngine.WARN_THRESHOLD, verdict.risk().explain());
    }

    @Test
    void startupScriptTargetIsReported() {
        PersistenceEntry entry = new PersistenceEntry("startup-task", EntryType.STARTUP_FOLDER, "Updater",
                "powershell -file C:\\Scripts\\job.ps1 /silent", "Startup", "", "test");

        ThreatVerdict verdict = analyzer.analysePersistence(entry);

        assertNotNull(verdict);
        assertTrue(verdict.indicators().contains("script target"), verdict.indicators().toString());
        assertTrue(verdict.risk().score() >= 30, verdict.risk().explain());
    }

    @Test
    void unsignedProcessOnCommonlyAbusedPortIsReported() throws IOException {
        ProcessSnapshot owner = ProcessSnapshot.basic(31337, 1, "helper.exe")
                .withSignature(SignatureInfo.unsigned());
        owner = owner.withDetails(temp.resolve("helper.exe").toString(), "", "user", Instant.now());
        Files.writeString(temp.resolve("helper.exe"), "placeholder");
        NetworkConnection connection = new NetworkConnection(31337, "tcp", "10.0.0.5", 51234,
                "203.0.113.9", 4444, "ESTABLISHED", "", Instant.now());

        ThreatVerdict verdict = analyzer.analyseNetwork(connection, owner);

        assertNotNull(verdict);
        assertTrue(verdict.risk().reasons().stream()
                .anyMatch(r -> r.code().equals("network.bad_port")),
                verdict.risk().explain());
    }

    @Test
    void ddnsHostOnOutboundConnectionIsReported() throws IOException {
        ProcessSnapshot owner = ProcessSnapshot.basic(31338, 1, "helper2.exe")
                .withSignature(SignatureInfo.unsigned());
        owner = owner.withDetails(temp.resolve("helper2.exe").toString(), "", "user", Instant.now());
        Files.writeString(temp.resolve("helper2.exe"), "placeholder");
        NetworkConnection connection = new NetworkConnection(31338, "tcp", "10.0.0.5", 51234,
                "203.0.113.44", 443, "ESTABLISHED", "", Instant.now());

        ThreatVerdict verdict = analyzer.analyseNetwork(connection, owner, "panel-srv.duckdns.org");

        assertNotNull(verdict);
        assertTrue(verdict.risk().reasons().stream()
                .anyMatch(r -> r.code().equals("network.ddns")), verdict.risk().explain());
    }

    @Test
    void nonNetworkingApplicationOpeningConnectionIsReported() {
        String windir = System.getenv("SystemRoot");
        String base = windir == null || windir.isBlank() ? "C:\\Windows" : windir;
        ProcessSnapshot notepad = ProcessSnapshot.basic(70, 1, "notepad.exe")
                .withDetails(base + "\\System32\\notepad.exe", "", "user", Instant.now())
                .withSignature(new SignatureInfo(true, SignatureInfo.Status.VALID,
                        "Microsoft Corporation", "CN=Microsoft", null, null, "test"));
        NetworkConnection connection = new NetworkConnection(70, "tcp", "10.0.0.5", 51234,
                "8.8.8.8", 443, "ESTABLISHED", "", Instant.now());

        ThreatVerdict verdict = analyzer.analyseNetwork(connection, notepad, "dns.google");

        assertNotNull(verdict);
        assertTrue(verdict.risk().reasons().stream()
                .anyMatch(r -> r.code().equals("network.process_mismatch")), verdict.risk().explain());
    }

    @Test
    void reconBurstIsReported() {
        String windir = System.getenv("SystemRoot");
        String base = windir == null || windir.isBlank() ? "C:\\Windows" : windir;
        ProcessSnapshot whoami = ProcessSnapshot.basic(101, 2000, "whoami.exe")
                .withDetails(base + "\\System32\\whoami.exe", "whoami /all", "user", Instant.now());
        ProcessSnapshot ipconfig = ProcessSnapshot.basic(102, 2000, "ipconfig.exe")
                .withDetails(base + "\\System32\\ipconfig.exe", "ipconfig /all", "user", Instant.now());
        ProcessSnapshot netstat = ProcessSnapshot.basic(103, 2000, "netstat.exe")
                .withDetails(base + "\\System32\\netstat.exe", "netstat -ano", "user", Instant.now());

        analyzer.analyseProcess(whoami, Map.of());
        analyzer.analyseProcess(ipconfig, Map.of());
        ThreatVerdict verdict = analyzer.analyseProcess(netstat, Map.of());

        assertNotNull(verdict);
        assertTrue(verdict.risk().reasons().stream()
                .anyMatch(r -> r.code().equals("behaviour.recon_loop")), verdict.risk().explain());
    }

    @Test
    void shellSpawnedByConsumerAppIsReported() {
        String windir = System.getenv("SystemRoot");
        String base = windir == null || windir.isBlank() ? "C:\\Windows" : windir;
        ProcessSnapshot discord = ProcessSnapshot.basic(40, 1, "Discord.exe")
                .withDetails("C:\\Users\\user\\AppData\\Local\\Discord\\Discord.exe", "", "user", Instant.now());
        ProcessSnapshot shell = ProcessSnapshot.basic(41, 40, "cmd.exe")
                .withDetails(base + "\\System32\\cmd.exe", "/c whoami", "user", Instant.now());

        ThreatVerdict verdict = analyzer.analyseProcess(shell, Map.of(40L, discord));

        assertNotNull(verdict);
        assertTrue(verdict.risk().reasons().stream()
                .anyMatch(r -> r.code().equals("process.consumer_app_parent")), verdict.risk().explain());
    }

    @Test
    void unsignedHiddenProcessInUserFolderIsReported() throws IOException {
        ProcessSnapshot process = snapshot(555, "gdpr-agent.exe", temp.resolve("gdpr-agent.exe"), "")
                .withSignature(SignatureInfo.unsigned())
                .withWindow(false);

        ThreatVerdict verdict = analyzer.analyseProcess(process, Map.of());

        assertNotNull(verdict);
        assertTrue(verdict.risk().reasons().stream()
                .anyMatch(r -> r.code().equals("behaviour.hidden_user_process")), verdict.risk().explain());
    }

    @Test
    void nullInputsAreHandled() {
        assertNull(analyzer.analyseProcess(null, null));
        assertNull(analyzer.analyseNetwork(null, null));
        assertNull(analyzer.analysePersistence(null));
    }
}
