package com.ratshield.core;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class StringExtractor {
    public record Indicator(String code, String label) {
    }

    public record Result(Set<String> strings, Set<Indicator> indicators, boolean truncated) {
    }

    private static final long MAX_SCAN_BYTES = 12L * 1024 * 1024;
    private static final int MIN_STRING = 5;

    private static final Pattern URL = Pattern.compile("(?i)https?://[a-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]{4,200}");
    private static final Pattern DISCORD_WEBHOOK = Pattern.compile("(?i)discord(app)?\\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+");
    private static final Pattern TELEGRAM = Pattern.compile("(?i)api\\.telegram\\.org/bot[0-9]+:[A-Za-z0-9_-]+");
    private static final Pattern BASE64_BLOB = Pattern.compile("[A-Za-z0-9+/]{120,}={0,2}");

    public static Result extract(Path file) throws IOException {
        Set<String> strings = new LinkedHashSet<>();
        boolean truncated = false;
        try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "r")) {
            long size = raf.length();
            long toRead = Math.min(size, MAX_SCAN_BYTES);
            if (size > MAX_SCAN_BYTES) {
                truncated = true;
            }
            byte[] head = new byte[(int) toRead];
            raf.readFully(head);
            collect(head, strings);
            if (size > MAX_SCAN_BYTES) {
                int tailLen = (int) Math.min(2L * 1024 * 1024, size);
                byte[] tail = new byte[tailLen];
                raf.seek(size - tailLen);
                raf.readFully(tail);
                collect(tail, strings);
            }
        }
        return analyse(strings, truncated);
    }

    public static Result analyseBytes(byte[] data) {
        Set<String> strings = new LinkedHashSet<>();
        collect(data == null ? new byte[0] : data, strings);
        return analyse(strings, false);
    }

    private static Result analyse(Set<String> strings, boolean truncated) {
        Set<Indicator> indicators = new LinkedHashSet<>();
        String joined = String.join(" ", strings).toLowerCase(Locale.ROOT);
        String rawJoined = String.join(" ", strings);
        detectIndicators(joined, rawJoined, indicators);
        return new Result(strings, indicators, truncated);
    }

    public static Set<Indicator> analyseText(String text) {
        Set<Indicator> indicators = new LinkedHashSet<>();
        detectIndicators(text == null ? "" : text.toLowerCase(Locale.ROOT), text == null ? "" : text, indicators);
        return indicators;
    }

    private static void detectIndicators(String lower, String original, Set<Indicator> out) {
        addIf(lower, out, "powershell_invocation", "Invokes PowerShell", "powershell");
        addIf(lower, out, "powershell_encoded", "Encoded PowerShell command", "-encodedcommand");
        addIf(lower, out, "powershell_encoded", "Encoded PowerShell command", "-enc ");
        addIf(lower, out, "powershell_hidden", "Hidden PowerShell window", "-w hidden");
        addIf(lower, out, "powershell_hidden", "Hidden PowerShell window", "-windowstyle hidden");
        addIf(lower, out, "powershell_bypass", "Execution policy bypass", "-exec bypass");
        addIf(lower, out, "powershell_download", "PowerShell download cradle", "invoke-webrequest");
        addIf(lower, out, "powershell_download", "PowerShell download cradle", "invoke-expression");
        addIf(lower, out, "cmd_invocation", "Spawns command shell", "cmd.exe /c");
        addIf(lower, out, "cmd_invocation", "Spawns command shell", "cmd.exe /k");
        addIf(lower, out, "wscript", "Windows Script Host host process", "wscript.exe");
        addIf(lower, out, "mshta", "HTA script host", "mshta.exe");
        addIf(lower, out, "rundll32", "Rundll32 loader", "rundll32.exe");
        addIf(lower, out, "regsvr32", "Regsvc32 registration utility", "regsvr32.exe");
        addIf(lower, out, "certutil_download", "Certutil used for download", "certutil -urlcache");
        addIf(lower, out, "bitsadmin", "Bitsadmin transfer", "bitsadmin /transfer");
        addIf(lower, out, "reg_persistence", "Registry run-key persistence", "\\currentversion\\run");
        addIf(lower, out, "reg_persistence", "Registry run-key persistence", "\\currentversion\\runonce");
        addIf(lower, out, "startup_persistence", "Startup folder persistence", "\\start menu\\programs\\startup");
        addIf(lower, out, "schtasks", "Scheduled task creation", "schtasks /create");
        addIf(lower, out, "service_persistence", "Service installation", "createservice");
        addIf(lower, out, "service_persistence", "Service installation", "new-service");
        addIf(lower, out, "wmipersistence", "WMI event subscription", "__eventfilter");
        addIf(lower, out, "wmipersistence", "WMI event subscription", "activescripteventconsumer");
        addIf(lower, out, "process_injection", "Process injection API", "virtualallocex");
        addIf(lower, out, "process_injection", "Process injection API", "writeprocessmemory");
        addIf(lower, out, "process_injection", "Process injection API", "createremotethread");
        addIf(lower, out, "process_injection", "Process injection API", "ntmapviewofsection");
        addIf(lower, out, "process_injection", "Process injection API", "queueuserapc");
        addIf(lower, out, "keylogging", "Keyboard hook API", "setwindowshookex");
        addIf(lower, out, "keylogging", "Keyboard state API", "getasynckeystate");
        addIf(lower, out, "keylogging", "Keyboard state API", "getkeystate");
        addIf(lower, out, "credential_access", "Windows credential store API", "cryptprotectdata");
        addIf(lower, out, "credential_access", "Windows credential store API", "lsass");
        addIf(lower, out, "credential_access", "Browser login database", "login data");
        addIf(lower, out, "credential_access", "Browser login database", "logins.json");
        addIf(lower, out, "credential_access", "Browser cookie store", "\\cookies\\");
        addIf(lower, out, "credential_access", "Saved credential enumeration", "cmdkey /list");
        addIf(lower, out, "defense_evasion", "Disables Windows Defender", "set-mppreference");
        addIf(lower, out, "defense_evasion", "Disables Windows Defender", "disableiavirusmonitoring");
        addIf(lower, out, "defense_evasion", "Deletes volume shadow copies", "vssadmin delete shadows");
        addIf(lower, out, "defense_evasion", "Deletes boot configuration", "bcdedit /set {default}");
        addIf(lower, out, "defense_evasion", "Clears security event logs", "wevtutil cl security");
        addIf(lower, out, "defense_evasion", "AMSI bypass indicator", "amsiinitfailed");
        addIf(lower, out, "anti_analysis", "Sandbox/user artifact check", "vmware");
        addIf(lower, out, "anti_analysis", "Sandbox/user artifact check", "virtualbox");
        addIf(lower, out, "anti_analysis", "Sandbox/user artifact check", "sandboxie");
        addIf(lower, out, "anti_analysis", "Sandbox/user artifact check", "ollydbg");
        addIf(lower, out, "anti_debug", "Debug API", "isdebuggerpresent");
        addIf(lower, out, "anti_debug", "Debug API", "checkremotedebugger");
        addIf(lower, out, "download_api", "URL download API", "urldownloadtofile");
        addIf(lower, out, "download_api", "HTTP client API", "internetopenurl");
        addIf(lower, out, "download_api", "HTTP client API", "winhttpconnect");
        addIf(lower, out, "download_api", "HTTP client API", "internetopen");
        addIf(lower, out, "socket", "Raw socket API", "wsasocket");
        addIf(lower, out, "socket", "Raw socket API", "socket(");
        addIf(lower, out, "screen_capture", "Screen capture API", "bitblt");
        addIf(lower, out, "screen_capture", "Screen capture API", "getdc(");
        addIf(lower, out, "webcam", "Camera capture API", "capcreatecapturewindow");
        addIf(lower, out, "persistence_file", "Drops into appdata", "\\appdata\\roaming\\");
        addIf(lower, out, "persistence_file", "Drops into local appdata", "\\appdata\\local\\temp\\");
        addIf(lower, out, "wallet", "Crypto wallet theft target", "wallet.dat");
        addIf(lower, out, "wallet", "Crypto wallet theft target", "seed phrase");
        addIf(lower, out, "clipboard", "Clipboard monitor API", "getclipboarddata");
        addIf(lower, out, "autostart_enum", "Autostart enumeration", "autoruns");
        addIf(lower, out, "remote_desktop", "Remote desktop indicator", "mstsc.exe");
        addIf(lower, out, "teamviewer", "Remote access tool indicator", "teamviewer");
        addIf(lower, out, "anydesk", "Remote access tool indicator", "anydesk");

        Matcher urlMatcher = URL.matcher(original);
        int urlCount = 0;
        Set<String> hosts = new LinkedHashSet<>();
        while (urlMatcher.find() && urlCount < 50) {
            String url = urlMatcher.group();
            urlCount++;
            if (!url.toLowerCase(Locale.ROOT).startsWith("http://schemas.")
                    && !url.toLowerCase(Locale.ROOT).startsWith("http://www.microsoft.com")
                    && !url.toLowerCase(Locale.ROOT).contains("w3.org")) {
                hosts.add(url);
            }
        }
        if (!hosts.isEmpty()) {
            out.add(new Indicator("embedded_url", "Contains embedded URLs (" + hosts.size() + ")"));
        }
        if (DISCORD_WEBHOOK.matcher(original).find()) {
            out.add(new Indicator("discord_webhook", "Discord webhook endpoint (common exfiltration)"));
        }
        if (TELEGRAM.matcher(original).find()) {
            out.add(new Indicator("telegram_bot", "Telegram bot API token (common exfiltration)"));
        }
        Matcher b64 = BASE64_BLOB.matcher(original);
        if (b64.find()) {
            out.add(new Indicator("base64_blob", "Large base64 blob (possible obfuscated payload)"));
        }
    }

    private static void addIf(String haystack, Set<Indicator> out, String code, String label, String needle) {
        if (haystack.contains(needle)) {
            out.add(new Indicator(code, label));
        }
    }

    private static void collect(byte[] data, Set<String> out) {
        StringBuilder current = new StringBuilder();
        for (byte b : data) {
            int c = b & 0xFF;
            if (c >= 32 && c < 127) {
                current.append((char) c);
            } else {
                if (current.length() >= MIN_STRING) {
                    out.add(current.toString());
                    if (out.size() > 40000) {
                        return;
                    }
                }
                current.setLength(0);
            }
        }
        if (current.length() >= MIN_STRING) {
            out.add(current.toString());
        }
        StringBuilder cur16 = new StringBuilder();
        for (int i = 0; i + 1 < data.length; i += 2) {
            int lo = data[i] & 0xFF;
            int hi = data[i + 1] & 0xFF;
            if (hi == 0 && lo >= 32 && lo < 127) {
                cur16.append((char) lo);
            } else {
                if (cur16.length() >= MIN_STRING) {
                    out.add(cur16.toString());
                    if (out.size() > 40000) {
                        return;
                    }
                }
                cur16.setLength(0);
            }
        }
    }

    public static List<String> topIndicators(Result result) {
        List<String> list = new ArrayList<>();
        for (Indicator i : result.indicators()) {
            list.add(i.code());
        }
        return list;
    }
}
