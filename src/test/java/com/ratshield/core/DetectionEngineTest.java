package com.ratshield.core;

import com.ratshield.TestSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DetectionEngineTest {

    @TempDir
    Path temp;

    @Test
    void eicarFileIsAConfirmedThreat() throws IOException {
        Path file = temp.resolve("eicar.com");
        Files.write(file, TestSupport.eicar());

        DetectionEngine.Result result = TestSupport.detection()
                .analyse(file, DetectionEngine.Request.defaults());
        ThreatVerdict verdict = result.verdict();

        assertFalse(result.analysis().ruleMatches().isEmpty());
        assertTrue(verdict.matchedRules().contains("Test_EICAR"));
        assertEquals(RecommendedAction.QUARANTINE, verdict.action());
        assertEquals(ThreatVerdict.Confidence.CONFIRMED, verdict.confidence());
        assertTrue(verdict.isThreat());
        assertTrue(verdict.isMalicious());
        assertTrue(verdict.risk().score() >= RiskEngine.WARN_THRESHOLD, verdict.risk().explain());
        assertFalse(verdict.detectionName().isBlank());
        assertTrue(verdict.risk().explain().contains("Test_EICAR"), verdict.risk().explain());
    }

    @Test
    void eicarIsRecognisedByItsReputationHash() throws IOException {
        Path file = temp.resolve("clean-looking.txt");
        Files.write(file, TestSupport.eicar());

        DetectionEngine.Result result = TestSupport.detection()
                .analyse(file, DetectionEngine.Request.defaults());
        assertEquals("EICAR-Standard-Antivirus-Test-File", result.analysis().reputationLabel());
        assertTrue(result.verdict().isMalicious());
    }

    @Test
    void harmlessFileIsAllowed() throws IOException {
        Path file = temp.resolve("notes.txt");
        Files.writeString(file, "Shopping list: milk, eggs, bread. Call the dentist on Friday.");

        DetectionEngine.Result result = TestSupport.detection()
                .analyse(file, DetectionEngine.Request.defaults());
        ThreatVerdict verdict = result.verdict();

        assertTrue(result.analysis().ruleMatches().isEmpty());
        assertTrue(verdict.matchedRules().isEmpty());
        assertEquals("No.Detection", verdict.detectionName());
        assertEquals(RecommendedAction.ALLOW, verdict.action());
        assertFalse(verdict.isThreat());
        assertTrue(verdict.risk().score() < RiskEngine.WARN_THRESHOLD, verdict.risk().explain());
    }

    @Test
    void doubleExtensionFileIsFlagged() throws IOException {
        Path file = temp.resolve("invoice.pdf.exe");
        Files.write(file, "MZ".getBytes(StandardCharsets.US_ASCII));

        DetectionEngine.Result result = TestSupport.detection()
                .analyse(file, DetectionEngine.Request.defaults());
        assertTrue(result.analysis().isDoubleExtension());
        assertTrue(result.verdict().indicators().stream().anyMatch(i -> i.contains("double extension")),
                result.verdict().indicators().toString());
        assertTrue(result.verdict().risk().score() >= 20, result.verdict().risk().explain());
    }

    @Test
    void missingFileProducesAnErrorRatherThanAnException() {
        DetectionEngine.Result result = TestSupport.detection()
                .analyse(temp.resolve("does-not-exist.exe"), DetectionEngine.Request.defaults());
        assertTrue(result.analysis().isAnalysisError(), "a missing file must be reported as an error");
        assertFalse(result.analysis().analysisErrorDetail() == null
                || result.analysis().analysisErrorDetail().isBlank());
    }

    @Test
    void archiveBytesAreAnalysedInMemory() {
        byte[] payload = TestSupport.eicar();
        DetectionEngine.Result result = TestSupport.detection().analyseBytes(
                temp.resolve("archive.zip"), "eicar.com", payload, payload.length, true,
                DetectionEngine.Request.defaults());
        assertTrue(result.analysis().isFromArchive());
        assertTrue(result.verdict().matchedRules().contains("Test_EICAR"));
        assertEquals(RecommendedAction.QUARANTINE, result.verdict().action());
    }

    @Test
    void spacePaddedFileNameIsFlagged() throws IOException {
        Path file = temp.resolve("important-report      .exe");
        Files.write(file, "hello".getBytes(StandardCharsets.US_ASCII));

        DetectionEngine.Result result = TestSupport.detection()
                .analyse(file, DetectionEngine.Request.defaults());

        assertTrue(result.verdict().risk().reasons().stream()
                .anyMatch(r -> r.code().equals("extension.padded")), result.verdict().risk().explain());
        assertTrue(result.verdict().risk().score() >= 18, result.verdict().risk().explain());
    }

    @Test
    void highEntropyNonExecutableDownloadIsFlagged() throws IOException {
        Path downloads = Files.createDirectories(temp.resolve("downloads"));
        Path file = downloads.resolve("payload.bin");
        byte[] noise = new byte[8192];
        new java.util.Random(42).nextBytes(noise);
        Files.write(file, noise);

        DetectionEngine.Result result = TestSupport.detection()
                .analyse(file, DetectionEngine.Request.defaults());

        assertTrue(result.verdict().risk().reasons().stream()
                        .anyMatch(r -> r.code().equals("entropy.high")),
                result.verdict().risk().explain());
    }

    @Test
    void jarWithRemoteControlIndicatorsIsFlaggedThroughTheEngine() throws IOException {
        Path jar = temp.resolve("agent.jar");
        try (java.util.zip.ZipOutputStream zos =
                     new java.util.zip.ZipOutputStream(Files.newOutputStream(jar))) {
            zos.putNextEntry(new java.util.zip.ZipEntry("com/example/Stage.class"));
            zos.write("Class.forName; ProcessBuilder cmd.exe /c; HttpURLConnection"
                    .getBytes(StandardCharsets.ISO_8859_1));
            zos.closeEntry();
        }

        DetectionEngine.Result result = TestSupport.detection()
                .analyse(jar, DetectionEngine.Request.defaults());

        assertTrue(result.verdict().risk().reasons().stream()
                .anyMatch(r -> r.code().equals("jar.process_exec")), result.verdict().risk().explain());
        assertTrue(result.verdict().risk().reasons().stream()
                .anyMatch(r -> r.code().equals("jar.network")), result.verdict().risk().explain());
    }
}
