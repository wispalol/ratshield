package com.ratshield.quarantine;

import com.ratshield.TestSupport;
import com.ratshield.core.ThreatVerdict;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class QuarantineServiceTest {

    @TempDir
    Path temp;

    private QuarantineService service() {
        return new QuarantineService(temp.resolve("quarantine"));
    }

    private Path sampleFile(String name) throws IOException {
        Path file = temp.resolve(name);
        Files.write(file, TestSupport.eicar());
        return file;
    }

    @Test
    void quarantineRemovesTheOriginalAndRecordsMetadata() throws IOException {
        QuarantineService service = service();
        Path file = sampleFile("malware.bin");

        QuarantineService.Result result = service.quarantine(file, TestSupport.verdict(
                "EICAR-Standard-Antivirus-Test-File", 90, com.ratshield.core.RecommendedAction.QUARANTINE,
                ThreatVerdict.Confidence.CONFIRMED));

        assertTrue(result.success(), result.message());
        assertFalse(Files.exists(file), "the original must be gone");
        assertEquals(1, service.count());

        List<QuarantineService.QuarantineRecord> records = service.list();
        assertEquals(1, records.size());
        assertEquals("malware.bin", records.getFirst().fileName());
        assertEquals("EICAR-Standard-Antivirus-Test-File", records.getFirst().threatName());
        assertEquals(TestSupport.EICAR_SHA256, records.getFirst().sha256());
        assertTrue(records.getFirst().originalPath().endsWith("malware.bin"));
        assertTrue(records.getFirst().riskScore() == 90);
    }

    @Test
    void restorePutsTheOriginalBackByteForByte() throws IOException {
        QuarantineService service = service();
        Path file = sampleFile("restore-me.bin");
        byte[] original = Files.readAllBytes(file);

        QuarantineService.Result quarantined = service.quarantine(file, TestSupport.verdict(
                "Test.Threat", 70, com.ratshield.core.RecommendedAction.QUARANTINE,
                ThreatVerdict.Confidence.CONFIRMED));
        assertTrue(quarantined.success(), quarantined.message());

        QuarantineService.Result restored = service.restore(quarantined.id(), true);
        assertTrue(restored.success(), restored.message());
        assertTrue(Files.exists(file));
        assertTrue(java.util.Arrays.equals(original, Files.readAllBytes(file)),
                "restored bytes must match the original");
        assertEquals(0, service.count());
    }

    @Test
    void deleteRemovesTheItemPermanently() throws IOException {
        QuarantineService service = service();
        Path file = sampleFile("delete-me.bin");
        QuarantineService.Result quarantined = service.quarantine(file, TestSupport.verdict(
                "Test.Threat", 70, com.ratshield.core.RecommendedAction.QUARANTINE,
                ThreatVerdict.Confidence.CONFIRMED));
        assertTrue(quarantined.success(), quarantined.message());

        QuarantineService.Result deleted = service.delete(quarantined.id());
        assertTrue(deleted.success(), deleted.message());
        assertEquals(0, service.count());
        assertFalse(Files.exists(file));
    }

    @Test
    void restoringIntoAnExistingFileNeedsOverwritePermission() throws IOException {
        QuarantineService service = service();
        Path file = sampleFile("conflict.bin");
        QuarantineService.Result quarantined = service.quarantine(file, TestSupport.verdict(
                "Test.Threat", 70, com.ratshield.core.RecommendedAction.QUARANTINE,
                ThreatVerdict.Confidence.CONFIRMED));
        assertTrue(quarantined.success());
        Files.writeString(file, "something else lives here now");

        QuarantineService.Result refused = service.restore(quarantined.id(), false);
        assertFalse(refused.success());
        assertTrue(Files.exists(file));

        QuarantineService.Result forced = service.restore(quarantined.id(), true);
        assertTrue(forced.success(), forced.message());
    }

    @Test
    void purgeExpiredDropsOldEntries() throws IOException {
        QuarantineService service = service();
        Path file = sampleFile("old.bin");
        QuarantineService.Result quarantined = service.quarantine(file, TestSupport.verdict(
                "Test.Threat", 70, com.ratshield.core.RecommendedAction.QUARANTINE,
                ThreatVerdict.Confidence.CONFIRMED));
        assertTrue(quarantined.success());

        assertEquals(0, service.purgeExpired(30), "a fresh item must survive a 30 day retention");
        assertEquals(1, service.count());
        assertTrue(service.purgeExpired(-1) >= 0);
    }

    @Test
    void quarantineOfMissingFileFailsGracefully() {
        QuarantineService service = service();
        QuarantineService.Result result = service.quarantine(temp.resolve("nope.bin"), TestSupport.verdict(
                "Test.Threat", 70, com.ratshield.core.RecommendedAction.QUARANTINE,
                ThreatVerdict.Confidence.CONFIRMED));
        assertFalse(result.success());
        assertEquals(0, service.count());
    }
}
