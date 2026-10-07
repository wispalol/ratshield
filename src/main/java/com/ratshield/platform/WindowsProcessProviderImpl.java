package com.ratshield.platform;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public final class WindowsProcessProviderImpl implements WindowsProcessProvider {
    private record Meta(long pid, long ppid, String name, String path, String commandLine, Boolean hasWindow) {
    }

    private record Cache(Set<Long> pids, Map<Long, Meta> meta, Instant at, boolean fromCim) {
    }

    private static final Duration QUERY_TIMEOUT = Duration.ofSeconds(20);
    private static final long MIN_REFRESH_MS = 5000;
    private static final long CACHE_TTL_MS = 15000;

    private volatile Cache cache;
    private volatile String lastError = "";
    private final List<String> diagnostics = new ArrayList<>();

    @Override
    public List<ProcessSnapshot> listProcesses() {
        return listProcesses(true);
    }

    @Override
    public List<ProcessSnapshot> listProcesses(boolean enrich) {
        Map<Long, ProcessSnapshot> base = fromProcessHandle();
        if (!enrich) {
            return sort(new ArrayList<>(base.values()));
        }
        Cache current = cache;
        long now = System.currentTimeMillis();
        boolean needsRefresh = current == null
                || (now - current.at().toEpochMilli() > MIN_REFRESH_MS
                && (!current.pids().equals(base.keySet()) || now - current.at().toEpochMilli() > CACHE_TTL_MS));
        if (needsRefresh) {
            current = refresh(base.keySet());
        }
        List<ProcessSnapshot> out = new ArrayList<>(base.size());
        for (ProcessSnapshot snapshot : base.values()) {
            Meta meta = current.meta().get(snapshot.pid());
            if (meta != null) {
                String name = meta.name().isBlank() ? snapshot.name() : meta.name();
                String path = meta.path().isBlank() ? snapshot.path() : meta.path();
                String cmd = meta.commandLine().isBlank() ? snapshot.commandLine() : meta.commandLine();
                long ppid = meta.ppid() > 0 ? meta.ppid() : snapshot.ppid();
                out.add(new ProcessSnapshot(snapshot.pid(), ppid, name, path, cmd, snapshot.startTime(),
                        snapshot.user(), snapshot.sha256(), snapshot.signature(), snapshot.riskScore(),
                        meta.hasWindow()));
            } else {
                out.add(snapshot);
            }
        }
        return sort(out);
    }

    private Cache refresh(Set<Long> pids) {
        Map<Long, Meta> meta = new HashMap<>();
        boolean fromCim = false;
        String script = "$w = @{}; Get-Process | Where-Object { $_.MainWindowHandle -ne 0 } | "
                + "ForEach-Object { $w[[int]$_.Id] = $true }; "
                + "Get-CimInstance Win32_Process | ForEach-Object { [pscustomobject]@{ "
                + "ProcessId = $_.ProcessId; ParentProcessId = $_.ParentProcessId; Name = $_.Name; "
                + "ExecutablePath = $_.ExecutablePath; CommandLine = $_.CommandLine; "
                + "HasWindow = [bool]$w[[int]$_.ProcessId] } } | ConvertTo-Json -Compress";
        CommandRunner.Result result = CommandRunner.run(QUERY_TIMEOUT, "powershell", "-NoProfile", "-NonInteractive",
                "-Command", script);
        if (result.ok() && !result.stdout().isBlank()) {
            try {
                JsonElement root = JsonParser.parseString(result.stdout().trim());
                JsonArray array;
                if (root.isJsonArray()) {
                    array = root.getAsJsonArray();
                } else {
                    array = new JsonArray();
                    array.add(root);
                }
                for (JsonElement element : array) {
                    if (!element.isJsonObject()) {
                        continue;
                    }
                    JsonObject obj = element.getAsJsonObject();
                    Meta m = new Meta(
                            getLong(obj, "ProcessId"),
                            getLong(obj, "ParentProcessId"),
                            getString(obj, "Name"),
                            getString(obj, "ExecutablePath"),
                            getString(obj, "CommandLine"),
                            getBoolean(obj, "HasWindow"));
                    meta.put(m.pid(), m);
                }
                fromCim = !meta.isEmpty();
            } catch (RuntimeException e) {
                lastError = "failed to parse process metadata: " + e.getMessage();
            }
        } else {
            lastError = result.unavailable() ? "PowerShell unavailable" : "process query failed: " + result.stderr().trim();
        }
        Cache newCache = new Cache(Set.copyOf(pids), meta, Instant.now(), fromCim);
        cache = newCache;
        return newCache;
    }

    private Map<Long, ProcessSnapshot> fromProcessHandle() {
        Map<Long, ProcessSnapshot> map = new HashMap<>();
        ProcessHandle.allProcesses().forEach(handle -> {
            try {
                long pid = handle.pid();
                long ppid = handle.parent().map(ProcessHandle::pid).orElse(-1L);
                String commandLine = handle.info().commandLine().orElse("");
                String command = handle.info().command().orElse("");
                String path = command;
                String name = imageOf(command, commandLine);
                if (name.isBlank()) {
                    name = "pid-" + pid;
                }
                Instant start = handle.info().startInstant().orElse(null);
                map.put(pid, new ProcessSnapshot(pid, ppid, name, path, commandLine, start, "", "", null, 0, null));
            } catch (RuntimeException ignored) {
                // process exited while enumerating
            }
        });
        return map;
    }

    private static String imageOf(String command, String commandLine) {
        String source = command;
        if (source.isBlank() && !commandLine.isBlank()) {
            source = commandLine.trim();
            if (source.startsWith("\"")) {
                int end = source.indexOf('"', 1);
                source = end > 0 ? source.substring(1, end) : source.substring(1);
            } else {
                int space = source.indexOf(' ');
                source = space > 0 ? source.substring(0, space) : source;
            }
        }
        if (source.isBlank()) {
            return "";
        }
        source = source.replace("\"", "");
        int slash = Math.max(source.lastIndexOf('\\'), source.lastIndexOf('/'));
        return slash >= 0 && slash < source.length() - 1 ? source.substring(slash + 1) : source;
    }

    @Override
    public Optional<ProcessSnapshot> snapshot(long pid) {
        return listProcesses(true).stream().filter(p -> p.pid() == pid).findFirst();
    }

    @Override
    public String owner(long pid) {
        String script = "$p = Get-CimInstance Win32_Process -Filter 'ProcessId=" + pid + "'; "
                + "if ($p) { $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner; "
                + "if ($o -and $o.User) { if ($o.Domain) { '{0}\\{1}' -f $o.Domain, $o.User } else { $o.User } } }";
        try {
            CommandRunner.Result result = CommandRunner.run(Duration.ofSeconds(10), "powershell", "-NoProfile",
                    "-NonInteractive", "-Command", script);
            if (result.ok()) {
                return result.stdout().trim();
            }
        } catch (RuntimeException ignored) {
            // handled below
        }
        return "";
    }

    @Override
    public boolean terminate(long pid) {
        Optional<ProcessHandle> handle = ProcessHandle.of(pid);
        if (handle.isEmpty()) {
            return false;
        }
        ProcessHandle target = handle.get();
        if (target.pid() == ProcessHandle.current().pid()) {
            return false;
        }
        boolean destroyed = target.destroy();
        if (!destroyed) {
            destroyed = target.destroyForcibly();
        }
        try {
            Thread.sleep(300);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return !target.isAlive() || destroyed;
    }

    @Override
    public List<String> diagnostics() {
        List<String> out = new ArrayList<>(diagnostics);
        if (!lastError.isBlank()) {
            out.add(lastError);
        }
        Cache current = cache;
        if (current != null && !current.fromCim()) {
            out.add("Win32 process metadata unavailable; showing data from the JVM process table only");
        }
        return out;
    }

    private static long getLong(JsonObject obj, String field) {
        try {
            if (obj.has(field) && obj.get(field).isJsonPrimitive()) {
                return obj.get(field).getAsLong();
            }
        } catch (RuntimeException ignored) {
            // fall through
        }
        return -1;
    }

    private static String getString(JsonObject obj, String field) {
        try {
            if (obj.has(field) && obj.get(field).isJsonPrimitive()) {
                return obj.get(field).getAsString();
            }
        } catch (RuntimeException ignored) {
            // fall through
        }
        return "";
    }

    private static Boolean getBoolean(JsonObject obj, String field) {
        try {
            if (obj.has(field) && obj.get(field).isJsonPrimitive()) {
                return obj.get(field).getAsBoolean();
            }
        } catch (RuntimeException ignored) {
            // fall through
        }
        return null;
    }

    private static List<ProcessSnapshot> sort(List<ProcessSnapshot> list) {
        list.sort(Comparator.comparingLong(ProcessSnapshot::pid));
        return list;
    }

    public static Set<String> knownSystemImageNames() {
        Set<String> names = new HashSet<>();
        for (String n : List.of("system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
                "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe", "explorer.exe",
                "idle", "memory compression", "securityhealthservice.exe", "spoolsv.exe", "searchindexer.exe",
                "sihost.exe", "taskhostw.exe", "runtimebroker.exe", "shellexperiencehost.exe",
                "startmenuexperiencehost.exe", "applicationframehost.exe", "ctfmon.exe", "msmpeng.exe")) {
            names.add(n.toLowerCase(Locale.ROOT));
        }
        return names;
    }
}
