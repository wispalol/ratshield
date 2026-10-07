package com.ratshield.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertTrue;

class JarAnalyzerTest {

    @TempDir
    Path temp;

    @Test
    void harmlessJarProducesNoFactors() throws IOException {
        Path jar = jarFile("util.jar", "com/example/Helper.class", "plain helper class");

        assertTrue(JarAnalyzer.scan(jar).isEmpty());
    }

    @Test
    void jarWithNetworkAndProcessExecutionIsFlagged() throws IOException {
        String payload = "class Stage { Class.forName(\"x\"); new ProcessBuilder(\"cmd.exe\",\"/c\").start(); "
                + "HttpURLConnection c = (HttpURLConnection) url.openConnection(); }";
        Path jar = jarFile("agent.jar", "com/example/Stage.class", payload,
                "com/example/QuasarRAT.class", "code");

        List<RiskFactor> factors = JarAnalyzer.scan(jar);

        assertTrue(anyCode(factors, "jar.process_exec"), factors.toString());
        assertTrue(anyCode(factors, "jar.network"), factors.toString());
        assertTrue(anyCode(factors, "jar.known_rat_family"), factors.toString());
    }

    @Test
    void jarWithKeylogHooksIsFlagged() throws IOException {
        String payload = "GetAsyncKeyState(1); SetWindowsHookEx(WH_KEYBOARD); BitBlt(0,0,1,1,hdc,0,0,SRCCOPY);";
        Path jar = jarFile("spy.jar", "com/example/Recorder.class", payload);

        List<RiskFactor> factors = JarAnalyzer.scan(jar);

        assertTrue(anyCode(factors, "jar.native_hooks"), factors.toString());
    }

    @Test
    void byteArrayScanOnlyRunsForJars() {
        assertTrue(JarAnalyzer.scan("not a jar".getBytes(StandardCharsets.UTF_8), "notes.txt").isEmpty());
    }

    private static boolean anyCode(List<RiskFactor> factors, String code) {
        return factors.stream().anyMatch(f -> f.code().equals(code));
    }

    private Path jarFile(String name, String... pair) throws IOException {
        Path jar = temp.resolve(name);
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(jar))) {
            for (int i = 0; i + 1 < pair.length; i += 2) {
                zos.putNextEntry(new ZipEntry(pair[i]));
                zos.write(pair[i + 1].getBytes(StandardCharsets.ISO_8859_1));
                zos.closeEntry();
            }
        }
        return jar;
    }
}