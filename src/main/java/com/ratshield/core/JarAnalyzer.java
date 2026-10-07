package com.ratshield.core;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Walks JAR/ZIP archives looking for the class-level hallmarks of Java remote access
 * trojans: dynamic class loading, shell execution, raw sockets, native hooks and script
 * evaluation. Every finding maps to an explainable {@link RiskFactor}.
 */
public final class JarAnalyzer {
    public static final int MAX_ENTRIES = 4000;
    public static final int MAX_CLASSES = 1500;
    public static final long MAX_TOTAL_BYTES = 24L * 1024 * 1024;
    public static final int MAX_ENTRY_BYTES = 4 * 1024 * 1024;

    private static final Map<String, PatternGroup> GROUPS = new LinkedHashMap<>();

    static {
        GROUPS.put("jar.dynamic_loading", new PatternGroup(
                "JAR loads classes at runtime (possible downloader/stager)",
                14, Severity.HIGH,
                "class.forname", "defineclass", "urlclassloader", "secureclassloader",
                "childclassloader", "methodhandle"));
        GROUPS.put("jar.process_exec", new PatternGroup(
                "JAR launches external processes or shells",
                16, Severity.HIGH,
                "processbuilder", "java/lang/runtime", "cmd.exe", "powershell.exe", "/c start"));
        GROUPS.put("jar.network", new PatternGroup(
                "JAR opens raw network connections (possible command and control)",
                10, Severity.MEDIUM,
                "httpurlconnection", "java/net/socket", "socketchannel", "datagramsocket",
                "websocket", "ftpclient", "jsch"));
        GROUPS.put("jar.native_hooks", new PatternGroup(
                "JAR uses native keyboard/screen capture or JNI hooks",
                15, Severity.HIGH,
                "setwindowshookex", "getasynckeystate", "getkeystate", "getforegroundwindow",
                "bitblt", "createcompatiblebitmap", "printwindow", "getpixel",
                "jni_onload", "system.load"));
        GROUPS.put("jar.script_eval", new PatternGroup(
                "JAR evaluates embedded scripts",
                12, Severity.HIGH,
                "javax/script", "scriptengine", "invokescript", "groovyshel", "bsh.interpreter"));
    }

    private static final List<String> KNOWN_RAT_TOKENS = List.of(
            "quasarrat", "asyncrat", "njrat", "darkcomet", "bladabindi", "warzone", "orcus",
            "adyluz", "mercstealer", "limbo rat");

    private JarAnalyzer() {
    }

    private record PatternGroup(String label, int points, Severity severity, String... tokens) {
    }

    public static List<RiskFactor> scan(Path path) {
        if (path == null) {
            return List.of();
        }
        try (InputStream in = Files.newInputStream(path)) {
            return scan(in);
        } catch (IOException e) {
            return List.of();
        }
    }

    public static List<RiskFactor> scan(byte[] data, String name) {
        if (data == null || name == null || !name.toLowerCase(Locale.ROOT).endsWith(".jar")) {
            return List.of();
        }
        return scan(new ByteArrayInputStream(data));
    }

    private static List<RiskFactor> scan(InputStream raw) {
        List<String> ratNames = new ArrayList<>();
        boolean[] hit = new boolean[GROUPS.size()];
        long budget = MAX_TOTAL_BYTES;
        int classes = 0;
        int entries = 0;
        try (ZipInputStream zip = new ZipInputStream(raw, StandardCharsets.UTF_8)) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null && entries < MAX_ENTRIES && classes < MAX_CLASSES) {
                entries++;
                if (entry.isDirectory()) {
                    continue;
                }
                String entryName = entry.getName().toLowerCase(Locale.ROOT);
                String flat = entryName.replace('/', '.');
                for (String token : KNOWN_RAT_TOKENS) {
                    if (flat.contains(token)) {
                        ratNames.add(entry.getName());
                    }
                }
                boolean isClass = entryName.endsWith(".class") && !entryName.contains("module-info");
                byte[] data = readEntry(zip, MAX_ENTRY_BYTES);
                if (data == null || data.length == 0 || budget <= 0) {
                    continue;
                }
                budget -= data.length;
                if (isClass) {
                    classes++;
                    String content = new String(data, StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT);
                    int index = 0;
                    for (Map.Entry<String, PatternGroup> group : GROUPS.entrySet()) {
                        if (hit[index]) {
                            index++;
                            continue;
                        }
                        for (String token : group.getValue().tokens()) {
                            if (content.contains(token)) {
                                hit[index] = true;
                                break;
                            }
                        }
                        index++;
                    }
                    if (allHit(hit)) {
                        break;
                    }
                }
            }
        } catch (IOException | RuntimeException e) {
            return List.of();
        }
        List<RiskFactor> factors = new ArrayList<>();
        int index = 0;
        for (Map.Entry<String, PatternGroup> group : GROUPS.entrySet()) {
            if (hit[index]) {
                PatternGroup g = group.getValue();
                factors.add(new RiskFactor(group.getKey(), g.label(), g.points(), g.severity()));
            }
            index++;
        }
        if (!ratNames.isEmpty()) {
            factors.add(new RiskFactor("jar.known_rat_family",
                    "Archive contains classes named after known RAT families: "
                            + ratNames.stream().distinct().limit(3).toList(),
                    20, Severity.HIGH));
        }
        return factors;
    }

    private static boolean allHit(boolean[] hit) {
        for (boolean b : hit) {
            if (!b) {
                return false;
            }
        }
        return true;
    }

    private static byte[] readEntry(InputStream in, int limit) throws IOException {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(Math.min(limit, 8192));
        byte[] buffer = new byte[8192];
        int total = 0;
        while (total < limit) {
            int read = in.read(buffer, 0, Math.min(buffer.length, limit - total));
            if (read < 0) {
                break;
            }
            out.write(buffer, 0, read);
            total += read;
        }
        return out.toByteArray();
    }
}
