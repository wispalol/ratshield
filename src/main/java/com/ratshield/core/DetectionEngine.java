package com.ratshield.core;

import com.ratshield.core.rules.RuleEngine;
import com.ratshield.platform.SignatureInfo;
import com.ratshield.platform.SignatureProvider;
import com.ratshield.util.FileIo;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Combines static analysis, local rules, reputation data and observed behaviour into a
 * single explainable verdict. No single indicator can produce a confident verdict on its own.
 */
public final class DetectionEngine {
    public static final long PARTIAL_HASH_THRESHOLD = 256L * 1024 * 1024;
    public static final long RECENT_DOWNLOAD_SECONDS = 900;

    public record Request(BehavioralContext behaviour, boolean verifySignature, boolean analyseStrings,
                          boolean allowRemoteReputation) {
        public static Request defaults() {
            return new Request(new BehavioralContext(), true, true, false);
        }

        public static Request fast() {
            return new Request(new BehavioralContext(), false, false, false);
        }

        public Request withBehaviour(BehavioralContext ctx) {
            return new Request(ctx, verifySignature, analyseStrings, allowRemoteReputation);
        }
    }

    public record Result(FileAnalysis analysis, ThreatVerdict verdict) {
    }

    private static final Set<String> INJECTION_APIS = Set.of(
            "virtualallocex", "writeprocessmemory", "createremotethread", "ntmapviewofsection",
            "queueuserapc", "ntunmapviewofsection", "setwindowshookex", "createthread",
            "rtlcreateuserthread", "setthreadcontext");
    private static final Set<String> KEYLOG_APIS = Set.of(
            "getasynckeystate", "getkeystate", "getforegroundwindow", "getwindowtexta", "getwindowtextw");
    private static final Set<String> CREDENTIAL_APIS = Set.of(
            "cryptunprotectdata", "credenumeratea", "credenumeratew", "lsaretrieveprivatedata",
            "samqueryinformationuse", "miniDumpWriteDump", "logonusera", "logonuserw");
    private static final Set<String> DOWNLOAD_APIS = Set.of(
            "urldownloadtofilea", "urldownloadtofilew", "internetopenurla", "internetopenurlw",
            "winhttpconnect", "winhttpopen", "httpsendrequest", "internetreadfile");
    private static final Set<String> DEBUG_APIS = Set.of(
            "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
            "outputdebugstringa", "ntsetinformationthread");
    private static final Set<String> PRIVILEGE_APIS = Set.of(
            "adjusttokenprivileges", "lookupprivilegevaluea", "lookupprivilegevaluew",
            "openprocesstoken", "duplicatetokenex", "createtokenuser");
    private static final Set<String> SCREEN_APIS = Set.of(
            "bitblt", "stretchblt", "getdc", "getwindowdc", "printwindow",
            "createcompatiblebitmap", "getpixel", "grabdesktop");

    private final RuleEngine ruleEngine;
    private final ReputationService reputationService;
    private final SignatureProvider signatureProvider;
    private final RiskEngine riskEngine;

    public DetectionEngine(RuleEngine ruleEngine, ReputationService reputationService,
                           SignatureProvider signatureProvider, RiskEngine riskEngine) {
        this.ruleEngine = ruleEngine;
        this.reputationService = reputationService;
        this.signatureProvider = signatureProvider;
        this.riskEngine = riskEngine;
    }

    public RuleEngine ruleEngine() {
        return ruleEngine;
    }

    public ReputationService reputationService() {
        return reputationService;
    }

    public Result analyse(Path path, Request request) {
        FileAnalysis analysis = new FileAnalysis().setPath(path).setBehavior(request.behaviour());
        try {
            BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class);
            analysis.setSize(attrs.size())
                    .setCreated(attrs.creationTime() == null ? null : attrs.creationTime().toInstant())
                    .setModified(attrs.lastModifiedTime() == null ? null : attrs.lastModifiedTime().toInstant());
            if (attrs.size() > PARTIAL_HASH_THRESHOLD) {
                analysis.setSha256(HashEngine.sha256OfString("partial:" + path + ":" + attrs.size()))
                        .setHashPartial(true);
            } else {
                analysis.setSha256(HashEngine.sha256(path));
            }
            byte[] head = FileIo.readHead(path, 64 * 1024);
            applyClassification(analysis, path.getFileName() == null ? path.toString() : path.getFileName().toString(), head);
            analysis.setEntropy(sampleEntropy(path, head));

            boolean executableLike = FileClassifier.isExecutableLike(
                    FileClassifier.classify(analysis.fileName(), head));
            boolean ruleScanWorthy = executableLike || attrs.size() <= 32L * 1024 * 1024;
            byte[] content = null;
            if (ruleScanWorthy) {
                content = FileIo.readHead(path, RuleEngine.MAX_CONTENT_BYTES);
            }

            if (isPe(head) && request.verifySignature()) {
                PeInfo pe = PeParser.parse(path).orElse(null);
                analysis.setPeInfo(pe);
                if (pe != null) {
                    analysis.setSignatureInfo(signatureProvider.verify(path));
                }
            } else if (isPe(head)) {
                analysis.setPeInfo(PeParser.parse(path).orElse(null));
            }

            if (request.analyseStrings() && (executableLike || (content != null && content.length <= 8 * 1024 * 1024))) {
                StringExtractor.Result strings = StringExtractor.extract(path);
                for (StringExtractor.Indicator indicator : strings.indicators()) {
                    analysis.stringIndicatorCodes().add(indicator.code());
                    analysis.stringIndicatorLabels().add(indicator.label());
                }
            }

            if (content != null) {
                for (RuleMatch match : ruleEngine.evaluate(content, attrs.size(), analysis.sha256())) {
                    analysis.ruleMatches().add(match);
                }
            } else if (!analysis.sha256().isEmpty()) {
                for (RuleMatch match : ruleEngine.evaluate(new byte[0], attrs.size(), analysis.sha256())) {
                    analysis.ruleMatches().add(match);
                }
            }

            if ("jar".equals(analysis.extension()) || analysis.fileName().toLowerCase(Locale.ROOT).endsWith(".jar")) {
                analysis.engineFactors().addAll(JarAnalyzer.scan(path));
            }

            applyReputation(analysis, request);
            applyLocationFactors(analysis, path);
        } catch (IOException | RuntimeException e) {
            analysis.setAnalysisError(e.getMessage());
        }
        return new Result(analysis, verdict(analysis, request.behaviour()));
    }

    public Result analyseBytes(Path origin, String name, byte[] data, long declaredSize, boolean fullContent,
                               Request request) {
        FileAnalysis analysis = new FileAnalysis().setPath(origin).setFileName(name).setBehavior(request.behaviour());
        analysis.setSize(declaredSize > 0 ? declaredSize : data.length);
        analysis.setModified(Instant.now());
        applyClassification(analysis, name, data);
        analysis.setEntropy(EntropyAnalyzer.shannon(data));
        if (fullContent) {
            analysis.setSha256(HashEngine.sha256(data));
        }
        if (isPe(data)) {
            analysis.setPeInfo(PeParser.parse(data).orElse(null));
        }
        if (request.analyseStrings()) {
            StringExtractor.Result strings = StringExtractor.analyseBytes(data);
            for (StringExtractor.Indicator indicator : strings.indicators()) {
                analysis.stringIndicatorCodes().add(indicator.code());
                analysis.stringIndicatorLabels().add(indicator.label());
            }
        }
        for (RuleMatch match : ruleEngine.evaluate(data, analysis.size(), analysis.sha256())) {
            analysis.ruleMatches().add(match);
        }
        analysis.engineFactors().addAll(JarAnalyzer.scan(data, name));
        applyReputation(analysis, request);
        analysis.setFromArchive(true);
        return new Result(analysis, verdict(analysis, request.behaviour()));
    }

    private void applyClassification(FileAnalysis analysis, String name, byte[] head) {
        FileClassifier.Classification c = FileClassifier.classify(name, head);
        analysis.setExtension(c.extension())
                .setTrueExtension(c.trueExtension())
                .setDoubleExtension(c.doubleExtension())
                .setRightToLeftOverride(c.rightToLeftOverride())
                .setFileType(c.type());
    }

    private void applyReputation(FileAnalysis analysis, Request request) {
        if (analysis.sha256().isEmpty() || analysis.isHashPartial()) {
            return;
        }
        Optional<ReputationService.ReputationHit> hit = reputationService.lookup(analysis.sha256());
        if (hit.isEmpty() && request.allowRemoteReputation()) {
            hit = reputationService.lookupRemote(analysis.sha256());
        }
        hit.ifPresent(h -> {
            analysis.setReputationLabel(h.label()).setReputationSeverity(h.severity());
        });
    }

    private void applyLocationFactors(FileAnalysis analysis, Path path) {
        String lower = path.toString().toLowerCase(Locale.ROOT);
        BehavioralContext ctx = analysis.behavior();
        if (lower.contains("\\windows\\temp\\") || lower.contains("\\temp\\") || lower.contains("\\tmp\\")) {
            ctx.setInTemp(true);
        }
        if (lower.contains("\\appdata\\local\\temp\\")) {
            ctx.setInTemp(true);
            ctx.setInAppData(true);
        }
        if (lower.contains("\\appdata\\roaming\\") || lower.contains("\\appdata\\local\\")) {
            ctx.setInAppData(true);
        }
        if (lower.contains("\\start menu\\programs\\startup") || lower.contains("\\microsoft\\windows\\start menu")) {
            ctx.setInStartupLocation(true);
        }
        long age = analysis.modified() == null ? Long.MAX_VALUE
                : Duration.between(analysis.modified(), Instant.now()).getSeconds();
        if (age >= 0 && age <= RECENT_DOWNLOAD_SECONDS
                && (lower.contains("\\downloads\\") || lower.contains("\\temp\\") || lower.contains("\\appdata\\"))) {
            ctx.setRecentlyDownloaded(true, age);
        }
    }

    private ThreatVerdict verdict(FileAnalysis analysis, BehavioralContext behaviour) {
        List<RiskFactor> factors = buildFactors(analysis);
        RiskAssessment assessment = riskEngine.assess(factors);
        List<String> indicators = new ArrayList<>();
        for (RiskFactor factor : factors) {
            if (factor.points() > 0) {
                indicators.add(factor.label());
            }
        }
        for (String label : analysis.stringIndicatorLabels()) {
            if (!indicators.contains(label)) {
                indicators.add(label);
            }
        }
        List<String> rules = new ArrayList<>();
        Severity severity = Severity.fromScore(assessment.score());
        for (RuleMatch match : analysis.ruleMatches()) {
            rules.add(match.rule().name());
            severity = severity.max(match.rule().severity());
        }
        if (!analysis.reputationLabel().isEmpty()) {
            severity = severity.max(analysis.reputationSeverity());
        }
        String detection = detectionName(analysis, assessment);
        ThreatVerdict.Confidence confidence = mapConfidence(assessment, analysis);
        return new ThreatVerdict(detection, family(analysis), severity, confidence, assessment,
                assessment.action(), indicators, rules);
    }

    private List<RiskFactor> buildFactors(FileAnalysis analysis) {
        List<RiskFactor> factors = new ArrayList<>();
        BehavioralContext ctx = analysis.behavior();

        factors.addAll(analysis.engineFactors());

        if (!analysis.reputationLabel().isEmpty()) {
            factors.add(new RiskFactor("reputation.known_bad",
                    "Known threat in reputation database: " + analysis.reputationLabel(), 60,
                    analysis.reputationSeverity()));
        }

        for (RuleMatch match : analysis.ruleMatches()) {
            int points = switch (match.rule().severity()) {
                case CRITICAL -> 55;
                case HIGH -> 45;
                case MEDIUM -> 30;
                case LOW -> 15;
                default -> 10;
            };
            if (match.matchType().equals("hash")) {
                points = 60;
            }
            factors.add(new RiskFactor("rule." + match.rule().name(),
                    "Detection rule matched: " + match.rule().name() + " - " + match.rule().description(),
                    points, match.rule().severity()));
        }

        PeInfo pe = analysis.peInfo();
        SignatureInfo sig = analysis.signatureInfo();
        if (pe != null) {
            switch (sig.status()) {
                case VALID -> factors.add(new RiskFactor("signature.valid",
                        "Digitally signed by " + (sig.signer() == null || sig.signer().isBlank()
                                ? "an unknown publisher" : sig.signer()), -15, Severity.INFO));
                case NOT_SIGNED -> factors.add(new RiskFactor("pe.unsigned", "Unsigned executable", 15, Severity.MEDIUM));
                case HASH_MISMATCH, ERROR -> factors.add(new RiskFactor("signature.invalid",
                        "Signature present but does not verify", 25, Severity.HIGH));
                default -> factors.add(new RiskFactor("pe.unsigned",
                        "Executable without a verifiable signature", 10, Severity.LOW));
            }
            if (pe.isLikelyPacked()) {
                factors.add(new RiskFactor("entropy.packed",
                        String.format("Packed or obfuscated binary (section entropy %.2f)", pe.maxSectionEntropy()),
                        15, Severity.MEDIUM));
            }
            List<String> suspicious = suspiciousImports(pe);
            if (!suspicious.isEmpty()) {
                boolean injection = containsAny(pe, INJECTION_APIS);
                boolean credentials = containsAny(pe, CREDENTIAL_APIS);
                boolean screen = containsAny(pe, SCREEN_APIS);
                int points = injection ? 18 : credentials ? 18 : containsAny(pe, KEYLOG_APIS) ? 15
                        : screen ? 15 : containsAny(pe, DEBUG_APIS) ? 8 : 8;
                String category = injection ? "process-injection" : credentials ? "credential-access"
                        : containsAny(pe, KEYLOG_APIS) ? "keyboard-monitoring"
                        : screen ? "screen-capture"
                        : containsAny(pe, DEBUG_APIS) ? "anti-debugging" : "network-download";
                factors.add(new RiskFactor("pe.suspicious_imports",
                        "Imports " + category + " APIs: " + String.join(", ", suspicious.subList(0, Math.min(4, suspicious.size()))),
                        points, Severity.HIGH));
            }
            if (!analysis.fileType().isExecutable() && pe.isDll()) {
                factors.add(new RiskFactor("pe.library", "Dynamic library dropped outside system locations", 6, Severity.LOW));
            }
            if (pe.imports().size() <= 1 && !pe.isDll() && pe.sections().size() <= 2) {
                factors.add(new RiskFactor("pe.few_imports", "Almost no imports (possible shellcode stub)", 8, Severity.MEDIUM));
            }
            if (pe.compileTime() != null && pe.compileTime().isAfter(Instant.now().plus(Duration.ofDays(1)))) {
                factors.add(new RiskFactor("pe.clock", "Compile timestamp lies in the future", 5, Severity.LOW));
            }
        }

        if (analysis.isDoubleExtension()) {
            factors.add(new RiskFactor("extension.double",
                    "Deceptive double extension: " + analysis.fileName(), 20, Severity.HIGH));
        }
        if (analysis.isRightToLeftOverride()) {
            factors.add(new RiskFactor("extension.rtl",
                    "Filename contains a right-to-left override character", 25, Severity.HIGH));
        }
        if (FileClassifier.looksSpacePadded(analysis.fileName())) {
            factors.add(new RiskFactor("extension.padded",
                    "Filename padded with spaces to hide the real extension: " + analysis.fileName(),
                    18, Severity.HIGH));
        }
        if (analysis.entropy() >= 7.4 && analysis.size() >= 4096 && analysis.peInfo() == null
                && analysis.fileType() != FileType.ARCHIVE
                && (analysis.fileType().isExecutable() || ctx.isRecentlyDownloaded() || ctx.isInTemp()
                || ctx.isInAppData())) {
            factors.add(new RiskFactor("entropy.high",
                    String.format("Unusually high entropy content (base64/encryption or packed payload): %.2f",
                            analysis.entropy()),
                    12, Severity.MEDIUM));
        }

        String lowerPath = analysis.path() == null ? "" : analysis.path().toString().toLowerCase(Locale.ROOT);
        if (ctx.isInTemp()) {
            factors.add(new RiskFactor("location.temp", "Located in a temporary directory", 10, Severity.MEDIUM));
        }
        if (ctx.isInAppData() && !ctx.isInTemp()) {
            factors.add(new RiskFactor("location.appdata", "Located in the user AppData tree", 8, Severity.MEDIUM));
        }
        if (ctx.isInStartupLocation()) {
            factors.add(new RiskFactor("location.startup", "Located in a startup/persistence location", 15, Severity.HIGH));
        }
        if (lowerPath.contains("\\downloads\\")) {
            factors.add(new RiskFactor("location.downloads", "Located in a downloads folder", 5, Severity.LOW));
        }
        if (ctx.isRecentlyDownloaded()) {
            factors.add(new RiskFactor("recent.download",
                    "Created or modified in the last " + Math.max(1, ctx.downloadAgeSeconds()) + " seconds", 12, Severity.MEDIUM));
        }

        int stringPoints = 0;
        int stringHits = 0;
        for (String code : analysis.stringIndicatorCodes()) {
            int weight = switch (code) {
                case "process_injection", "keylogging", "credential_access", "defense_evasion" -> 6;
                case "powershell_encoded", "reg_persistence", "startup_persistence", "wmipersistence",
                     "service_persistence", "schtasks", "discord_webhook", "telegram_bot" -> 5;
                case "powershell_invocation", "cmd_invocation", "download_api", "base64_blob" -> 3;
                default -> 2;
            };
            if (stringPoints + weight <= 20) {
                stringPoints += weight;
                stringHits++;
            }
        }
        if (stringPoints > 0) {
            factors.add(new RiskFactor("string.indicators",
                    stringHits + " suspicious embedded string indicator(s) in the file", stringPoints, Severity.MEDIUM));
        }

        if (ctx.isSpawnedShellChild()) {
            factors.add(new RiskFactor("behaviour.spawned_shell", "Launches a shell/PowerShell child process", 12, Severity.HIGH));
        }
        if (ctx.isSpawnedEncodedShell()) {
            factors.add(new RiskFactor("behaviour.encoded_command", "Executes an encoded command line", 10, Severity.HIGH));
        }
        if (ctx.isPersistenceCreated()) {
            factors.add(new RiskFactor("behaviour.persistence_created", "Attempted to create a persistence entry", 17, Severity.HIGH));
        }
        if (ctx.isSuspiciousOutboundConnection()) {
            factors.add(new RiskFactor("behaviour.suspicious_connection",
                    "Opened an outbound connection to an external host", 12, Severity.MEDIUM));
        }
        if (ctx.isLongLivedExternalConnection()) {
            factors.add(new RiskFactor("behaviour.long_lived_connection",
                    "Maintains a long-lived external connection", 8, Severity.MEDIUM));
        }
        if (ctx.isNewProcessWithNetwork()) {
            factors.add(new RiskFactor("behaviour.new_process_network",
                    "Newly started process immediately opened a network connection", 10, Severity.MEDIUM));
        }
        if (ctx.isProcessInjection()) {
            factors.add(new RiskFactor("behaviour.process_injection", "Process-injection indicators observed", 20, Severity.CRITICAL));
        }
        if (ctx.isCredentialAccess()) {
            factors.add(new RiskFactor("behaviour.credential_access", "Credential-access behaviour observed", 18, Severity.CRITICAL));
        }
        if (ctx.isDefenseEvasion()) {
            factors.add(new RiskFactor("behaviour.defense_evasion", "Attempt to disable or bypass security tooling", 20, Severity.CRITICAL));
        }
        if (ctx.isSecurityToolTampering()) {
            factors.add(new RiskFactor("behaviour.security_tampering",
                    "Attempt to interfere with security software", 25, Severity.CRITICAL));
        }
        if (ctx.parentRiskScore() >= 40) {
            factors.add(new RiskFactor("behaviour.suspicious_parent",
                    "Started by a suspicious parent process (" + ctx.parentProcess() + ")", 10, Severity.MEDIUM));
        }
        if (ctx.suspiciousChildCount() > 0) {
            factors.add(new RiskFactor("behaviour.suspicious_children",
                    ctx.suspiciousChildCount() + " suspicious child process(es)", 8, Severity.MEDIUM));
        }
        return factors;
    }

    private static boolean containsAny(PeInfo pe, Set<String> needles) {
        for (Map.Entry<String, List<String>> entry : pe.imports().entrySet()) {
            for (String api : entry.getValue()) {
                if (needles.contains(api.toLowerCase(Locale.ROOT))) {
                    return true;
                }
            }
        }
        return false;
    }

    private static List<String> suspiciousImports(PeInfo pe) {
        List<String> found = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (Map.Entry<String, List<String>> entry : pe.imports().entrySet()) {
            for (String api : entry.getValue()) {
                String lower = api.toLowerCase(Locale.ROOT);
                if ((INJECTION_APIS.contains(lower) || KEYLOG_APIS.contains(lower) || CREDENTIAL_APIS.contains(lower)
                        || DOWNLOAD_APIS.contains(lower) || DEBUG_APIS.contains(lower) || PRIVILEGE_APIS.contains(lower)
                        || SCREEN_APIS.contains(lower))
                        && seen.add(lower)) {
                    found.add(api);
                }
            }
        }
        return found;
    }

    private String detectionName(FileAnalysis analysis, RiskAssessment assessment) {
        if (!analysis.reputationLabel().isEmpty() && assessment.score() >= 60) {
            return analysis.reputationLabel();
        }
        if (!analysis.ruleMatches().isEmpty()) {
            RuleMatch best = analysis.ruleMatches().stream()
                    .sorted((a, b) -> b.rule().severity().compareTo(a.rule().severity()))
                    .findFirst().orElseThrow();
            String family = best.rule().meta().get("family");
            if (family != null && !family.isBlank()) {
                return family;
            }
            return "Heur.Rule." + best.rule().name();
        }
        BehavioralContext ctx = analysis.behavior();
        boolean unsigned = analysis.peInfo() != null && analysis.signatureInfo().status() != SignatureInfo.Status.VALID;
        if (ctx.isProcessInjection()) {
            return "Suspicious.ProcessInjection.Behaviour";
        }
        if (ctx.isCredentialAccess()) {
            return "Suspicious.CredentialAccess.Behaviour";
        }
        if (ctx.isPersistenceCreated() && unsigned) {
            return "Suspicious.Persistence.UnsignedStartup";
        }
        if (ctx.isPersistenceCreated()) {
            return "Suspicious.Persistence.Behaviour";
        }
        if (ctx.isSuspiciousOutboundConnection() && ctx.isSpawnedShellChild()) {
            return "Suspicious.RemoteAccessBehaviour";
        }
        if (ctx.isSuspiciousOutboundConnection() && unsigned && ctx.isRecentlyDownloaded()) {
            return "Suspicious.RemoteAccessBehaviour";
        }
        if (analysis.isDoubleExtension()) {
            return "Heur.Deceptive.Executable";
        }
        if (analysis.peInfo() != null && analysis.peInfo().isLikelyPacked()) {
            return "Heur.Obfuscated.Executable";
        }
        if (unsigned && ctx.isRecentlyDownloaded() && (ctx.isInTemp() || ctx.isInAppData())) {
            return "Heur.Unsigned.SuspiciousDownload";
        }
        if (ctx.isSpawnedShellChild()) {
            return "Heur.SuspiciousProcess.SpawnsShell";
        }
        if (assessment.score() >= RiskEngine.WARN_THRESHOLD) {
            return "Heur.Suspicious.File";
        }
        return "No.Detection";
    }

    private static String family(FileAnalysis analysis) {
        if (!analysis.reputationLabel().isEmpty()) {
            return analysis.reputationLabel().contains(".")
                    ? analysis.reputationLabel().substring(0, analysis.reputationLabel().indexOf('.'))
                    : analysis.reputationLabel();
        }
        if (!analysis.ruleMatches().isEmpty()) {
            String family = analysis.ruleMatches().getFirst().rule().meta().get("family");
            return family == null ? "" : family;
        }
        return "";
    }

    private static ThreatVerdict.Confidence mapConfidence(RiskAssessment assessment, FileAnalysis analysis) {
        return switch (assessment.confidence()) {
            case "CONFIRMED" -> ThreatVerdict.Confidence.CONFIRMED;
            case "HIGH" -> ThreatVerdict.Confidence.HIGH;
            case "MEDIUM" -> ThreatVerdict.Confidence.MEDIUM;
            default -> ThreatVerdict.Confidence.LOW;
        };
    }

    private static boolean isPe(byte[] head) {
        return PeParser.looksLikePeHeader(head);
    }

    private static double sampleEntropy(Path path, byte[] head) {
        try {
            if (Files.size(path) <= head.length) {
                return EntropyAnalyzer.shannon(head);
            }
        } catch (IOException ignored) {
            // fall through to header-only entropy
        }
        return EntropyAnalyzer.shannon(head, 0, Math.min(head.length, 32 * 1024));
    }
}
