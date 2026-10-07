package com.ratshield.platform;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class WindowsPersistenceProviderImpl implements WindowsPersistenceProvider {
    private static final String[] RUN_KEYS = {
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
    };

    private final List<String> diagnostics = new ArrayList<>();

    @Override
    public List<PersistenceEntry> collect() {
        List<PersistenceEntry> entries = new ArrayList<>();
        collectRegistry(entries);
        collectStartupFolders(entries);
        collectScheduledTasks(entries);
        collectServices(entries);
        collectWmi(entries);
        return entries;
    }

    private void collectRegistry(List<PersistenceEntry> entries) {
        for (String key : RUN_KEYS) {
            CommandRunner.Result result = CommandRunner.run(Duration.ofSeconds(10), "reg", "query", key);
            if (result.unavailable() || !result.ok()) {
                if (!result.unavailable() && result.exitCode() == 1) {
                    continue;
                }
                if (!result.unavailable()) {
                    diagnostics.add("reg query failed for " + key + ": " + result.stderr().trim());
                }
                continue;
            }
            boolean runOnce = key.toLowerCase(Locale.ROOT).contains("runonce");
            String hive = key.startsWith("HKCU") ? "HKCU" : "HKLM";
            for (String line : result.lines()) {
                if (line.startsWith("HKEY_")) {
                    continue;
                }
                String upper = line.toUpperCase(Locale.ROOT);
                int typeIndex = upper.indexOf("REG_SZ");
                if (typeIndex < 0) {
                    typeIndex = upper.indexOf("REG_EXPAND_SZ");
                }
                if (typeIndex < 0) {
                    continue;
                }
                String name = line.substring(0, typeIndex).trim();
                String value = line.substring(typeIndex).replaceFirst("(?i)REG_(EXPAND_)?SZ", "").trim();
                if (name.isEmpty() || value.isEmpty()) {
                    continue;
                }
                EntryType type = runOnce ? EntryType.REGISTRY_RUNONCE : EntryType.REGISTRY_RUN;
                entries.add(new PersistenceEntry(stableId(type, hive + "\\" + key + "\\" + name), type,
                        name, value, key, "", "registry"));
            }
        }
    }

    private void collectStartupFolders(List<PersistenceEntry> entries) {
        List<Path> folders = new ArrayList<>();
        String appData = System.getenv("APPDATA");
        String programData = System.getenv("ProgramData");
        if (appData != null) {
            folders.add(Path.of(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"));
        }
        if (programData != null) {
            folders.add(Path.of(programData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"));
        }
        for (Path folder : folders) {
            if (!Files.isDirectory(folder)) {
                continue;
            }
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(folder)) {
                for (Path file : stream) {
                    String name = file.getFileName().toString();
                    String target = resolveShortcutTarget(file);
                    entries.add(new PersistenceEntry(stableId(EntryType.STARTUP_FOLDER, file.toString()),
                            EntryType.STARTUP_FOLDER, name, target, folder.toString(), "", "startup-folder"));
                }
            } catch (IOException e) {
                diagnostics.add("startup folder read failed: " + e.getMessage());
            }
        }
    }

    private String resolveShortcutTarget(Path file) {
        String lower = file.getFileName().toString().toLowerCase(Locale.ROOT);
        if (!lower.endsWith(".lnk")) {
            return file.toString();
        }
        CommandRunner.Result result = CommandRunner.run(Duration.ofSeconds(8), "powershell", "-NoProfile",
                "-NonInteractive", "-Command",
                "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('" + escape(file.toString()) + "'); $s.TargetPath");
        if (result.ok()) {
            String target = result.stdout().trim();
            if (!target.isEmpty()) {
                return target;
            }
        }
        return file.toString();
    }

    private void collectScheduledTasks(List<PersistenceEntry> entries) {
        String script = "Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { "
                + "$a = ''; try { $a = ($_.Actions | ForEach-Object { $_.Execute }) -join ';' } catch {}; "
                + "$ar = ''; try { $ar = ($_.Actions | ForEach-Object { $_.Arguments }) -join ';' } catch {}; "
                + "[pscustomobject]@{ n = $_.TaskName; p = $_.TaskPath; e = $a; a = $ar } } | ConvertTo-Json -Compress";
        CommandRunner.Result result = CommandRunner.run(Duration.ofSeconds(25), "powershell", "-NoProfile",
                "-NonInteractive", "-Command", script);
        if (result.unavailable() || !result.ok()) {
            if (!result.unavailable()) {
                diagnostics.add("scheduled task query failed: " + result.stderr().trim());
            }
            return;
        }
        try {
            JsonArray array = asArray(result.stdout());
            for (JsonElement element : array) {
                if (!element.isJsonObject()) {
                    continue;
                }
                JsonObject obj = element.getAsJsonObject();
                String name = get(obj, "n");
                String taskPath = get(obj, "p");
                String execute = get(obj, "e");
                String args = get(obj, "a");
                String target = execute + (args.isBlank() ? "" : " " + args);
                entries.add(new PersistenceEntry(stableId(EntryType.SCHEDULED_TASK, taskPath + name),
                        EntryType.SCHEDULED_TASK, taskPath + name, target.trim(), "Task Scheduler", "", "schtasks"));
            }
        } catch (RuntimeException e) {
            diagnostics.add("scheduled task parse failed: " + e.getMessage());
        }
    }

    private void collectServices(List<PersistenceEntry> entries) {
        String script = "Get-CimInstance Win32_Service | Select-Object Name,PathName,StartMode,State | ConvertTo-Json -Compress";
        CommandRunner.Result result = CommandRunner.run(Duration.ofSeconds(25), "powershell", "-NoProfile",
                "-NonInteractive", "-Command", script);
        if (result.unavailable() || !result.ok()) {
            if (!result.unavailable()) {
                diagnostics.add("service query failed: " + result.stderr().trim());
            }
            return;
        }
        try {
            JsonArray array = asArray(result.stdout());
            for (JsonElement element : array) {
                if (!element.isJsonObject()) {
                    continue;
                }
                JsonObject obj = element.getAsJsonObject();
                String name = get(obj, "Name");
                String pathName = get(obj, "PathName");
                String state = get(obj, "State");
                String mode = get(obj, "StartMode");
                String location = "Service (" + mode + ", " + state + ")";
                entries.add(new PersistenceEntry(stableId(EntryType.SERVICE, name), EntryType.SERVICE, name,
                        pathName, location, "", "scm"));
            }
        } catch (RuntimeException e) {
            diagnostics.add("service parse failed: " + e.getMessage());
        }
    }

    private void collectWmi(List<PersistenceEntry> entries) {
        String script = "$out = @(); "
                + "try { Get-CimInstance -Namespace root\\subscription -ClassName __EventFilter -ErrorAction Stop | "
                + "ForEach-Object { $out += [pscustomobject]@{ t='filter'; n=$_.Name; q=$_.Query } } } catch {}; "
                + "try { Get-CimInstance -Namespace root\\subscription -ClassName CommandLineEventConsumer -ErrorAction Stop | "
                + "ForEach-Object { $out += [pscustomobject]@{ t='consumer'; n=$_.Name; q=$_.CommandLineTemplate } } } catch {}; "
                + "$out | ConvertTo-Json -Compress";
        CommandRunner.Result result = CommandRunner.run(Duration.ofSeconds(20), "powershell", "-NoProfile",
                "-NonInteractive", "-Command", script);
        if (result.unavailable() || !result.ok()) {
            if (!result.unavailable() && !result.stdout().isBlank()) {
                diagnostics.add("WMI persistence query failed: " + result.stderr().trim());
            }
            return;
        }
        if (result.stdout().isBlank()) {
            return;
        }
        try {
            JsonArray array = asArray(result.stdout());
            for (JsonElement element : array) {
                if (!element.isJsonObject()) {
                    continue;
                }
                JsonObject obj = element.getAsJsonObject();
                String kind = get(obj, "t");
                String name = get(obj, "n");
                String query = get(obj, "q");
                if (name.isBlank()) {
                    continue;
                }
                entries.add(new PersistenceEntry(stableId(EntryType.WMI_SUBSCRIPTION, kind + name),
                        EntryType.WMI_SUBSCRIPTION, name, query, "WMI " + kind + " (root\\subscription)", "",
                        "wmi"));
            }
        } catch (RuntimeException e) {
            diagnostics.add("WMI persistence parse failed: " + e.getMessage());
        }
    }

    @Override
    public List<String> diagnostics() {
        return List.copyOf(diagnostics);
    }

    private static JsonArray asArray(String json) {
        JsonElement root = JsonParser.parseString(json.trim());
        if (root.isJsonArray()) {
            return root.getAsJsonArray();
        }
        JsonArray array = new JsonArray();
        array.add(root);
        return array;
    }

    private static String get(JsonObject obj, String field) {
        try {
            if (obj.has(field) && obj.get(field).isJsonPrimitive()) {
                return obj.get(field).getAsString();
            }
        } catch (RuntimeException ignored) {
            // fall through
        }
        return "";
    }

    private static String escape(String value) {
        return value.replace("'", "''");
    }

    private static String stableId(EntryType type, String key) {
        return type.name() + "-" + Integer.toHexString(key.toLowerCase(Locale.ROOT).hashCode());
    }

    public static String startupFolder() {
        String appData = System.getenv("APPDATA");
        return appData == null ? "" : Path.of(appData, "Microsoft", "Windows", "Start Menu", "Programs",
                "Startup").toString();
    }
}
