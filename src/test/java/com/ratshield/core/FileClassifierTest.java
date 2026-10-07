package com.ratshield.core;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileClassifierTest {

    @Test
    void doubleExtensionIsDetected() {
        FileClassifier.Classification c = FileClassifier.classify("invoice.pdf.exe", new byte[0]);
        assertTrue(c.doubleExtension());
        assertEquals("exe", c.extension());
        assertTrue(FileClassifier.isExecutableLike(c));
    }

    @Test
    void plainDocumentIsNotExecutableLike() {
        FileClassifier.Classification c = FileClassifier.classify("report.pdf", "%PDF-1.4".getBytes(StandardCharsets.US_ASCII));
        assertFalse(c.doubleExtension());
        assertFalse(FileClassifier.isExecutableLike(c));
    }

    @Test
    void executableMagicIsDetectedRegardlessOfName() {
        byte[] header = {'M', 'Z', (byte) 0x90, 0x00, 0x03};
        FileClassifier.Classification c = FileClassifier.classify("mystery.bin", header);
        assertTrue(FileClassifier.isExecutableLike(c));
        assertTrue(c.type().isExecutable());
    }

    @Test
    void rightToLeftOverrideIsFlagged() {
        FileClassifier.Classification c = FileClassifier.classify("invoice\u202Egpj.exe", new byte[0]);
        assertTrue(c.rightToLeftOverride());
    }

    @Test
    void spacePaddedExtensionIsFlagged() {
        assertTrue(FileClassifier.looksSpacePadded("invoice-2026-final         .exe"));
        assertTrue(FileClassifier.looksSpacePadded("scan report    .scr"));
        assertFalse(FileClassifier.looksSpacePadded("invoice-2026-final.exe"));
        assertFalse(FileClassifier.looksSpacePadded("normal file.txt"));
        assertFalse(FileClassifier.looksSpacePadded(""));
    }

    @Test
    void archiveNamesAreRecognised() {
        assertTrue(FileClassifier.looksLikeArchiveName("payload.zip"));
        assertTrue(FileClassifier.looksLikeArchiveName("backup.7z"));
        assertFalse(FileClassifier.looksLikeArchiveName("notes.txt"));
    }

    @Test
    void extensionOfHandlesMissingExtension() {
        assertEquals("exe", FileClassifier.extensionOf("setup.exe"));
        assertEquals("", FileClassifier.extensionOf("readme"));
    }
}
