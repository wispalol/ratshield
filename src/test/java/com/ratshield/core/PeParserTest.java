package com.ratshield.core;

import com.ratshield.util.FileIo;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PeParserTest {

    private static Path systemPe() {
        String windir = System.getenv("SystemRoot");
        Path candidate = Path.of(windir == null ? "C:\\Windows" : windir, "System32", "notepad.exe");
        return Files.isRegularFile(candidate) ? candidate : null;
    }

    @Test
    void randomBytesAreNotAPe() {
        assertTrue(PeParser.parse(new byte[64]).isEmpty());
        assertFalse(PeParser.looksLikePeHeader(new byte[64]));
        assertFalse(PeParser.looksLikePeHeader("MZ but nothing else".getBytes()));
    }

    @Test
    void realSystemPeParses() {
        Path pe = systemPe();
        Assumptions.assumeTrue(pe != null, "notepad.exe not available");
        PeInfo info = PeParser.parse(pe).orElseThrow();
        assertFalse(info.isDll());
        assertFalse(info.sections().isEmpty());
        assertFalse(info.imports().isEmpty());
        assertTrue(info.compileTime() != null || info.maxSectionEntropy() >= 0.0);
    }

    @Test
    void headerSniffMatchesTheParser() throws IOException {
        Path pe = systemPe();
        Assumptions.assumeTrue(pe != null, "notepad.exe not available");
        byte[] head = FileIo.readHead(pe, 64);
        assertTrue(PeParser.looksLikePeHeader(head));
        try {
            PeParser.parse(head);
        } catch (RuntimeException e) {
            throw new AssertionError("truncated header must not crash the parser", e);
        }
    }
}
