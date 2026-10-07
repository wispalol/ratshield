package com.ratshield.protection;

import com.ratshield.core.RecommendedAction;
import com.ratshield.core.RiskAssessment;
import com.ratshield.core.RiskEngine;
import com.ratshield.core.RiskFactor;
import com.ratshield.core.Severity;
import com.ratshield.core.ThreatVerdict;
import com.ratshield.platform.NetworkConnection;
import com.ratshield.platform.ProcessSnapshot;
import com.ratshield.platform.SignatureInfo;
import com.ratshield.platform.SignatureProvider;
import com.ratshield.platform.WindowsPersistenceProvider;
import com.ratshield.platform.WindowsPersistenceProvider.PersistenceEntry;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Turns live observations (processes, connections, auto-start entries) into the same
 * {@link ThreatVerdict} shape the file scanner produces, so every protection layer reports
 * through one vocabulary and one scoring model.
 *
 * <p>Every factor carries a human-readable label and the exact points it contributes; the UI
 * shows {@link RiskAssessment#explain()} next to every detection so the user can verify why an
 * action was taken rather than having to trust a black box.</p>
 */
public final class BehaviorAnalyzer {
    private static final Set<String> SHELLS = Set.of("powershell", "powershell_ise", "cmd", "wscript",
            "cscript", "mshta", "rundll32", "regsvr32", "regsvr32.exe", "certutil", "bitsadmin",
            "msbuild", "installutil", "cmstp", "verclsid");
    private static final Set<String> SYSTEM_IMAGES = Set.of("svchost", "lsass", "services", "winlogon",
            "csrss", "smss", "dwm", "wininit", "fontdrvhost", "searchindexer", "spoolsv", "taskhostw");
    private static final Set<String> OFFICE_PARENTS = Set.of("winword", "excel", "powerpnt", "outlook",
            "acrord32", "acrord64", "visio");
    private static final Set<String> UNUSUAL_PARENTS = Set.of("services", "winlogon", "lsass", "csrss",
            "smss", "wininit", "spoolsv");
    private static final Set<Integer> UNUSUAL_PORTS = Set.of(1337, 4444, 5555, 6666, 7777, 8081, 8888,
            9001, 12345, 27374, 31337);
    private static final Set<String> NON_NETWORK_APPS = Set.of("notepad", "notepad++", "calc", "calculator",
            "mspaint", "paint", "wordpad", "snippingtool", "snippingtoolwindow", "wscript", "cscript",
            "mshta", "regsvr32", "rundll32", "control", "eventvwr", "mmc", "taskschd", "charmap",
            "osk", "magnify");
    private static final Set<String> CONSUMER_APPS = Set.of("discord", "steam", "steamwebhelper", "spotify",
            "epicgameslauncher", "epicwebhelper", "battle.net", "telegram", "slack", "ms-teams", "teams",
            "msedge", "chrome", "firefox", "opera", "brave");
    private static final Set<String> RECON_TOOLS = Set.of("whoami", "ipconfig", "systeminfo", "hostname",
            "nltest", "net", "net1", "arp", "route", "tasklist", "quser", "query", "fsutil", "gpresult",
            "wmic", "netstat", "nslookup");
    private static final List<String> DDNS_SUFFIXES = List.of(
            ".duckdns.org", ".no-ip.com", ".no-ip.org", ".no-ip.net", ".dyndns.org", ".dyndns.net",
            ".hopto.org", ".zapto.org", ".noip.com", ".ngrok.io", ".ngrok-free.app", ".serveo.net",
            ".ddns.net", ".ddns.info", ".dynu.com", ".changeip.com", ".afraid.org", ".hopto.me");
    private static final long RECON_WINDOW_MS = 60_000;

    private static final String[] SUSPICIOUS_COMMAND_TOKENS = {
            "-enc", "-encodedcommand", "-e ", "frombase64string", "iex(", "invoke-expression",
            "downloadstring", "downloadfile", "invoke-webrequest", "-nop", "-w hidden", "-windowstyle hidden",
            "-noni", "bypass", "unblock-file", "add-mppreference", "exclusions", "amsiutils", "amsi.dll",
            "virtualprotect", "writeprocessmemory", "createremotethread", "set-mppreference"
    };

    private final RiskEngine riskEngine;
    private final SignatureProvider signatureProvider;
    private final Map<Long, ArrayDeque<ReconEvent>> reconWindows = new ConcurrentHashMap<>();

    private record ReconEvent(String tool, long atMs) {
    }

    public BehaviorAnalyzer(RiskEngine riskEngine, SignatureProvider signatureProvider) {
        this.riskEngine = riskEngine;
        this.signatureProvider = signatureProvider;
    }

    public ThreatVerdict analyseProcess(ProcessSnapshot process, Map<Long, ProcessSnapshot> context) {
        if (process == null) {
            return null;
        }
        String path = process.path();
        String name = baseName(process.name(), path);
        String commandLine = process.commandLine() == null ? "" : process.commandLine();
        String lowerCommand = commandLine.toLowerCase(Locale.ROOT);
        String lowerPath = path.toLowerCase(Locale.ROOT);
        boolean pathKnown = !path.isBlank();
        boolean systemLocation = isSystemLocation(lowerPath);

        List<RiskFactor> factors = new ArrayList<>();
        List<String> indicators = new ArrayList<>();

        SignatureInfo signature = process.signature();
        if (pathKnown && (signature == null || signature.status() == SignatureInfo.Status.UNKNOWN)) {
            signature = verifyQuietly(Path.of(path));
        }
        if (signature != null && signature.isVerified()) {
            factors.add(factor("signature.valid", "Signed by " + signature.signer(), -25, Severity.LOW));
        } else if (pathKnown && !systemLocation && signature != null
                && signature.status() == SignatureInfo.Status.NOT_SIGNED) {
            factors.add(factor("pe.unsigned", "Executable carries no code signature", 20, Severity.MEDIUM));
            indicators.add("unsigned executable");
        }

        if (pathKnown && !systemLocation
                && (isTempLocation(lowerPath) || isAppDataLocation(lowerPath))
                && (signature == null || !signature.isVerified())
                && Boolean.FALSE.equals(process.visibleWindow())) {
            factors.add(factor("behaviour.hidden_user_process",
                    "Unsigned process running from a user-writable folder with no visible window",
                    14, Severity.MEDIUM));
            indicators.add("hidden background process");
        }

        if (isTempLocation(lowerPath)) {
            factors.add(factor("location.temp", "Running from a temporary folder", 15, Severity.MEDIUM));
            indicators.add("temporary folder");
        } else if (isAppDataLocation(lowerPath)) {
            factors.add(factor("location.appdata", "Running from a user application-data folder", 12,
                    Severity.MEDIUM));
            indicators.add("application-data folder");
        } else if (isStartupLocation(lowerPath)) {
            factors.add(factor("location.startup", "Running from a startup folder", 18, Severity.MEDIUM));
            indicators.add("startup folder");
        } else if (isDownloadsLocation(lowerPath)) {
            factors.add(factor("recent.download", "Running straight from the Downloads folder", 8,
                    Severity.LOW));
            indicators.add("Downloads folder");
        }

        String normalizedName = name.toLowerCase(Locale.ROOT).replace(".exe", "");
        if (RECON_TOOLS.contains(normalizedName) && recordRecon(process.ppid(), normalizedName)) {
            factors.add(factor("behaviour.recon_loop",
                    "Reconnaissance burst: several network/user/system enumeration commands in quick succession",
                    16, Severity.MEDIUM));
            indicators.add("reconnaissance burst");
        }
        if (SHELLS.contains(normalizedName)) {
            factors.add(factor("behaviour.spawned_shell", "Command shell or script host: " + name,
                    12, Severity.MEDIUM));
            indicators.add(name + " command shell");
        }
        if (SYSTEM_IMAGES.contains(normalizedName) && pathKnown && !systemLocation) {
            factors.add(factor("process.system_lookalike",
                    "System process name '" + name + "' running from " + path, 40, Severity.HIGH));
            indicators.add("system process look-alike");
        }
        if (matchesAny(lowerCommand, SUSPICIOUS_COMMAND_TOKENS)) {
            factors.add(factor("behaviour.defense_evasion",
                    "Command line uses encoding, hidden window or security-bypass flags", 22, Severity.HIGH));
            indicators.add("obfuscated command line");
        }
        if (lowerCommand.contains("mimikatz") || lowerCommand.contains("sekurlsa")
                || lowerPath.contains("\\mimikatz")) {
            factors.add(factor("behaviour.credential_access", "References credential-dumping tooling",
                    35, Severity.HIGH));
            indicators.add("credential dumping reference");
        }
        if (lowerCommand.contains("http://") || lowerCommand.contains("https://")) {
            if (normalizedName.matches("mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec")) {
                factors.add(factor("process.lolbin",
                        name + " invoked with a remote URL argument", 30, Severity.HIGH));
                indicators.add("LOLBin with remote payload");
            }
        }

        ProcessSnapshot parent = context == null || process.ppid() <= 0 ? null : context.get(process.ppid());
        if (parent != null) {
            String parentBase = baseName(parent.name(), parent.path()).toLowerCase(Locale.ROOT)
                    .replace(".exe", "");
            if (CONSUMER_APPS.contains(parentBase) && SHELLS.contains(normalizedName)) {
                factors.add(factor("process.consumer_app_parent",
                        "Shell or script host started by a consumer application: " + parent.name(),
                        18, Severity.HIGH));
                indicators.add("spawned by " + parent.name());
            } else if (UNUSUAL_PARENTS.contains(parentBase) && normalizedName.matches("powershell|cmd|wscript|cscript|mshta|rundll32")) {
                factors.add(factor("process.unusual_parent",
                        "Started by system process " + parent.name(), 15, Severity.MEDIUM));
                indicators.add("parent " + parent.name());
            } else if (OFFICE_PARENTS.contains(parentBase)) {
                factors.add(factor("process.from_office",
                        "Started by document application " + parent.name(), 25, Severity.HIGH));
                indicators.add("spawned by " + parent.name());
            } else if (parent.riskScore() > 0 && parent.riskScore() >= RiskEngine.WARN_THRESHOLD) {
                factors.add(factor("process.parent_flagged",
                        "Parent process already scored " + parent.riskScore() + "/100",
                        15, Severity.MEDIUM));
                indicators.add("flagged parent process");
            }
        }
        if (pathKnown && !Files.exists(Path.of(path)) && !systemLocation) {
            factors.add(factor("process.image_missing",
                    "Image path reported by the OS no longer exists: " + path, 5, Severity.LOW));
        }

        if (factors.isEmpty()) {
            return null;
        }
        return verdict("Behavior.Process." + slug(name), "Behavioral", factors, indicators, name);
    }

    public ThreatVerdict analyseNetwork(NetworkConnection connection, ProcessSnapshot owner) {
        String host = connection == null ? "" : connection.hostname();
        return analyseNetwork(connection, owner, host);
    }

    public ThreatVerdict analyseNetwork(NetworkConnection connection, ProcessSnapshot owner, String hostname) {
        if (connection == null) {
            return null;
        }
        List<RiskFactor> factors = new ArrayList<>();
        List<String> indicators = new ArrayList<>();
        String endpoint = connection.endpoint();
        boolean external = connection.isExternal("");
        boolean listening = connection.isListener();

        boolean signed = owner != null && owner.isSigned();
        String ownerPath = owner == null ? "" : owner.path().toLowerCase(Locale.ROOT);
        boolean ownerSystem = ownerPath.isEmpty() || isSystemLocation(ownerPath);
        String ownerBase = owner == null ? ""
                : baseName(owner.name(), owner.path()).toLowerCase(Locale.ROOT).replace(".exe", "");

        if (external) {
            String resolved = hostname == null || hostname.isBlank() ? connection.hostname() : hostname;
            if (isDdnsHost(resolved)) {
                factors.add(factor("network.ddns",
                        "Dynamic-DNS host name \"" + resolved + "\" commonly used to mask remote control traffic",
                        16, Severity.HIGH));
                indicators.add(resolved);
            }
            if (owner != null && NON_NETWORK_APPS.contains(ownerBase)) {
                factors.add(factor("network.process_mismatch",
                        safeName(owner) + " is not a networking application but opened a connection to "
                                + endpoint, 18, Severity.HIGH));
                indicators.add(ownerBase + " outbound");
            }
            if (UNUSUAL_PORTS.contains(connection.remotePort())) {
                factors.add(factor("network.bad_port",
                        "Outbound connection to commonly-abused port " + connection.remotePort(),
                        14, Severity.MEDIUM));
                indicators.add("port " + connection.remotePort());
            }
            if (owner == null) {
                factors.add(factor("network.unattributed",
                        "Connection to " + endpoint + " belongs to a process that exited", 10, Severity.MEDIUM));
                indicators.add(endpoint);
            } else if (!signed && !ownerSystem) {
                factors.add(factor("behaviour.suspicious_connection",
                        "Unsigned application " + safeName(owner) + " opened a connection to " + endpoint,
                        25, Severity.HIGH));
                indicators.add(endpoint);
            }
        }
        if (listening && owner != null && !ownerSystem && !signed
                && (isTempLocation(ownerPath) || isAppDataLocation(ownerPath))) {
            factors.add(factor("behaviour.listener_untrusted",
                    safeName(owner) + " is listening on " + connection.localPort() + " from a user-writable location",
                    30, Severity.HIGH));
            indicators.add("listening on " + connection.localPort());
        }
        if (listening && UNUSUAL_PORTS.contains(connection.localPort()) && owner != null && !ownerSystem) {
            factors.add(factor("network.unusual_listener",
                    safeName(owner) + " listens on commonly-abused port " + connection.localPort(),
                    12, Severity.MEDIUM));
            indicators.add("port " + connection.localPort());
        }

        if (factors.isEmpty()) {
            return null;
        }
        String subject = owner == null ? connection.protocol() : safeName(owner);
        return verdict("Behavior.Network." + slug(subject), "Behavioral", factors, indicators, subject);
    }

    public ThreatVerdict analysePersistence(PersistenceEntry entry) {
        if (entry == null) {
            return null;
        }
        List<RiskFactor> factors = new ArrayList<>();
        List<String> indicators = new ArrayList<>();
        String target = entry.target() == null ? "" : entry.target();
        String lowerTarget = target.toLowerCase(Locale.ROOT);
        String targetPath = WindowsPersistenceProvider.targetPath(target);
        String lowerPath = targetPath.toLowerCase(Locale.ROOT);
        boolean executableTarget = WindowsPersistenceProvider.looksLikeExecutable(target);

        factors.add(factor("behaviour.persistence_created",
                "New auto-start entry: " + entry.type().name().toLowerCase(Locale.ROOT).replace('_', ' '),
                18, Severity.MEDIUM));
        indicators.add(entry.type().name());

        if (isTempLocation(lowerPath)) {
            factors.add(factor("location.temp", "Auto-start target lives in a temporary folder",
                    20, Severity.HIGH));
            indicators.add("temporary folder");
        } else if (isAppDataLocation(lowerPath)) {
            factors.add(factor("location.appdata", "Auto-start target lives in a user application-data folder",
                    14, Severity.MEDIUM));
            indicators.add("application-data folder");
        }

        if (executableTarget && !lowerPath.isBlank()) {
            Path file = Path.of(targetPath);
            if (Files.isRegularFile(file)) {
                SignatureInfo signature = verifyQuietly(file);
                if (signature.isVerified()) {
                    factors.add(factor("signature.valid", "Signed by " + signature.signer(), -25, Severity.LOW));
                } else if (signature.status() == SignatureInfo.Status.NOT_SIGNED) {
                    factors.add(factor("pe.unsigned", "Auto-start target carries no code signature",
                            22, Severity.HIGH));
                    indicators.add("unsigned target");
                } else {
                    factors.add(factor("signature.unknown", "Signature of auto-start target not verified",
                            6, Severity.LOW));
                }
            } else {
                factors.add(factor("persistence.missing_target",
                        "Auto-start target does not exist on disk: " + targetPath, 20, Severity.HIGH));
                indicators.add("missing target");
            }
        } else if (!executableTarget && !lowerTarget.isBlank()) {
            if (lowerTarget.contains(".ps1") || lowerTarget.contains(".vbs") || lowerTarget.contains(".js")
                    || lowerTarget.contains(".hta") || lowerTarget.contains(".bat") || lowerTarget.contains(".cmd")) {
                factors.add(factor("persistence.script_target", "Auto-start runs a script rather than a binary",
                        14, Severity.MEDIUM));
                indicators.add("script target");
            }
        }

        if (entry.type() == WindowsPersistenceProvider.EntryType.WMI_SUBSCRIPTION) {
            factors.add(factor("persistence.wmi", "WMI event subscription used for auto-start",
                    18, Severity.HIGH));
            indicators.add("WMI subscription");
        }
        if (entry.type() == WindowsPersistenceProvider.EntryType.REGISTRY_RUNONCE) {
            factors.add(factor("persistence.runonce", "RunOnce entry fires exactly once after reboot",
                    6, Severity.LOW));
        }
        if (lowerTarget.contains("-enc") || lowerTarget.contains("frombase64string")
                || lowerTarget.contains("downloadstring") || lowerTarget.contains("-nop -w hidden")) {
            factors.add(factor("behaviour.defense_evasion",
                    "Auto-start command line is encoded or hidden", 28, Severity.HIGH));
            indicators.add("encoded command");
        }
        if (lowerTarget.contains("schtasks") || lowerTarget.contains("/create")) {
            factors.add(factor("persistence.nested_task", "Auto-start launches a nested scheduled task",
                    16, Severity.MEDIUM));
        }
        if (entry.type() == WindowsPersistenceProvider.EntryType.SERVICE) {
            String systemRoot = System.getenv("SystemRoot");
            String lowerRoot = systemRoot == null ? "c:\\windows" : systemRoot.toLowerCase(Locale.ROOT);
            if (!lowerPath.isBlank() && !lowerPath.startsWith(lowerRoot)) {
                factors.add(factor("persistence.service_offsystem",
                        "Windows service binary lives outside the Windows directory: " + targetPath,
                        18, Severity.MEDIUM));
                indicators.add("service outside Windows directory");
            }
        }

        if (factors.size() <= 1 && entry.type() == WindowsPersistenceProvider.EntryType.SERVICE
                && isSystemLocation(lowerPath)) {
            return null;
        }
        String name = entry.name() == null || entry.name().isBlank() ? entry.type().name() : entry.name();
        return verdict("Behavior.Persistence." + slug(name), "Behavioral", factors, indicators, name);
    }

    private ThreatVerdict verdict(String detectionName, String family, List<RiskFactor> factors,
                                  List<String> indicators, String subject) {
        RiskAssessment risk = riskEngine.assess(factors);
        ThreatVerdict.Confidence confidence;
        try {
            confidence = ThreatVerdict.Confidence.valueOf(risk.confidence());
        } catch (IllegalArgumentException e) {
            confidence = ThreatVerdict.Confidence.LOW;
        }
        return new ThreatVerdict(detectionName, family, Severity.fromScore(risk.score()), confidence,
                risk, risk.action(), indicators, List.of());
    }

    private SignatureInfo verifyQuietly(Path file) {
        if (signatureProvider == null || file == null) {
            return SignatureInfo.unavailable("no signature provider");
        }
        try {
            SignatureInfo info = signatureProvider.verify(file);
            return info == null ? SignatureInfo.unavailable("no result") : info;
        } catch (RuntimeException e) {
            return SignatureInfo.unavailable("signature check failed: " + e.getMessage());
        }
    }

    private static RiskFactor factor(String code, String label, int points, Severity severity) {
        return new RiskFactor(code, label, points, severity);
    }

    private boolean recordRecon(long ppid, String tool) {
        if (ppid <= 0) {
            return false;
        }
        if (reconWindows.size() > 512) {
            reconWindows.clear();
        }
        long now = System.currentTimeMillis();
        ArrayDeque<ReconEvent> window = reconWindows.computeIfAbsent(ppid, k -> new ArrayDeque<>());
        boolean fired;
        synchronized (window) {
            window.addLast(new ReconEvent(tool, now));
            while (!window.isEmpty() && now - window.peekFirst().atMs() > RECON_WINDOW_MS) {
                window.pollFirst();
            }
            Set<String> distinct = new HashSet<>();
            for (ReconEvent event : window) {
                distinct.add(event.tool());
            }
            fired = window.size() >= 3 && distinct.size() >= 2;
            if (fired) {
                window.clear();
            }
            while (window.size() > 48) {
                window.pollFirst();
            }
        }
        return fired;
    }

    private static boolean isDdnsHost(String host) {
        if (host == null || host.isBlank()) {
            return false;
        }
        String lower = host.toLowerCase(Locale.ROOT).trim();
        if (lower.endsWith(".")) {
            lower = lower.substring(0, lower.length() - 1);
        }
        int colon = lower.lastIndexOf(':');
        if (colon > 0 && lower.indexOf(':') == colon) {
            lower = lower.substring(0, colon);
        }
        for (String suffix : DDNS_SUFFIXES) {
            if (lower.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }

    private static boolean matchesAny(String value, String[] needles) {
        for (String needle : needles) {
            if (value.contains(needle)) {
                return true;
            }
        }
        return false;
    }

    private static String safeName(ProcessSnapshot snapshot) {
        if (snapshot.name() != null && !snapshot.name().isBlank()) {
            return snapshot.name();
        }
        String path = snapshot.path();
        return path.isBlank() ? "pid " + snapshot.pid() : baseName(snapshot.name(), path);
    }

    private static String baseName(String name, String path) {
        if (name != null && !name.isBlank()) {
            return name;
        }
        if (path == null || path.isBlank()) {
            return "";
        }
        int index = Math.max(path.lastIndexOf('\\'), path.lastIndexOf('/'));
        return index >= 0 ? path.substring(index + 1) : path;
    }

    private static String slug(String value) {
        String cleaned = value == null ? "unknown" : value.replaceAll("[^A-Za-z0-9]+", "");
        return cleaned.isBlank() ? "Unknown" : cleaned.substring(0, Math.min(32, cleaned.length()));
    }

    static boolean isTempLocation(String lowerPath) {
        if (lowerPath == null || lowerPath.isBlank()) {
            return false;
        }
        if (lowerPath.startsWith("\\temp") || lowerPath.contains("\\appdata\\local\\temp")) {
            return true;
        }
        String temp = System.getenv("TEMP");
        if (temp != null && !temp.isBlank()) {
            return lowerPath.startsWith(temp.toLowerCase(Locale.ROOT));
        }
        return lowerPath.startsWith("/tmp/");
    }

    static boolean isAppDataLocation(String lowerPath) {
        if (lowerPath == null || lowerPath.isBlank()) {
            return false;
        }
        if (lowerPath.contains("\\appdata\\") || lowerPath.contains("\\application data\\")) {
            return true;
        }
        String local = System.getenv("LOCALAPPDATA");
        String roaming = System.getenv("APPDATA");
        if (local != null && !local.isBlank() && lowerPath.startsWith(local.toLowerCase(Locale.ROOT))) {
            return true;
        }
        return roaming != null && !roaming.isBlank()
                && lowerPath.startsWith(roaming.toLowerCase(Locale.ROOT));
    }

    static boolean isStartupLocation(String lowerPath) {
        return lowerPath != null && lowerPath.contains("\\start menu\\programs\\startup");
    }

    static boolean isDownloadsLocation(String lowerPath) {
        if (lowerPath == null || lowerPath.isBlank()) {
            return false;
        }
        if (lowerPath.contains("\\downloads\\")) {
            return true;
        }
        String home = System.getProperty("user.home", "");
        return !home.isBlank() && lowerPath.startsWith(home.toLowerCase(Locale.ROOT) + "\\downloads");
    }

    static boolean isSystemLocation(String lowerPath) {
        if (lowerPath == null || lowerPath.isBlank()) {
            return false;
        }
        String root = System.getenv("SystemRoot");
        String windows = root == null || root.isBlank() ? "c:\\windows" : root.toLowerCase(Locale.ROOT);
        return lowerPath.startsWith(windows + "\\system32")
                || lowerPath.startsWith(windows + "\\syswow64")
                || lowerPath.startsWith(windows + "\\winsxs")
                || lowerPath.startsWith(windows + "\\servicing")
                || lowerPath.startsWith(windows + "\\microsoft.net");
    }
}
