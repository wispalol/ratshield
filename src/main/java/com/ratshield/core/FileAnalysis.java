package com.ratshield.core;

import com.ratshield.platform.SignatureInfo;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Static facts collected about a single file. This object contains no verdicts — the
 * detection engine turns these facts into a {@link ThreatVerdict}.
 */
public final class FileAnalysis {
    private Path path;
    private String fileName;
    private long size;
    private Instant created;
    private Instant modified;
    private String extension;
    private String trueExtension;
    private boolean doubleExtension;
    private boolean rightToLeftOverride;
    private FileType fileType = FileType.UNKNOWN;
    private String sha256 = "";
    private boolean hashPartial;
    private double entropy;
    private PeInfo peInfo;
    private SignatureInfo signatureInfo = SignatureInfo.unsigned();
    private final Set<String> stringIndicatorCodes = new LinkedHashSet<>();
    private final Set<String> stringIndicatorLabels = new LinkedHashSet<>();
    private final List<RuleMatch> ruleMatches = new ArrayList<>();
    private final List<RiskFactor> engineFactors = new ArrayList<>();
    private String reputationLabel = "";
    private Severity reputationSeverity = Severity.INFO;
    private boolean fromArchive;
    private Path archivePath;
    private String archiveEntry;
    private BehavioralContext behavior = new BehavioralContext();
    private boolean analysisError;
    private String analysisErrorDetail = "";

    public Path path() {
        return path;
    }

    public FileAnalysis setPath(Path path) {
        this.path = path;
        if (path != null) {
            this.fileName = path.getFileName() == null ? path.toString() : path.getFileName().toString();
        }
        return this;
    }

    public String fileName() {
        return fileName;
    }

    public FileAnalysis setFileName(String fileName) {
        this.fileName = fileName;
        return this;
    }

    public long size() {
        return size;
    }

    public FileAnalysis setSize(long size) {
        this.size = size;
        return this;
    }

    public Instant created() {
        return created;
    }

    public FileAnalysis setCreated(Instant created) {
        this.created = created;
        return this;
    }

    public Instant modified() {
        return modified;
    }

    public FileAnalysis setModified(Instant modified) {
        this.modified = modified;
        return this;
    }

    public String extension() {
        return extension;
    }

    public FileAnalysis setExtension(String extension) {
        this.extension = extension;
        return this;
    }

    public String trueExtension() {
        return trueExtension;
    }

    public FileAnalysis setTrueExtension(String trueExtension) {
        this.trueExtension = trueExtension;
        return this;
    }

    public boolean isDoubleExtension() {
        return doubleExtension;
    }

    public FileAnalysis setDoubleExtension(boolean doubleExtension) {
        this.doubleExtension = doubleExtension;
        return this;
    }

    public boolean isRightToLeftOverride() {
        return rightToLeftOverride;
    }

    public FileAnalysis setRightToLeftOverride(boolean rightToLeftOverride) {
        this.rightToLeftOverride = rightToLeftOverride;
        return this;
    }

    public FileType fileType() {
        return fileType;
    }

    public FileAnalysis setFileType(FileType fileType) {
        this.fileType = fileType == null ? FileType.UNKNOWN : fileType;
        return this;
    }

    public String sha256() {
        return sha256;
    }

    public FileAnalysis setSha256(String sha256) {
        this.sha256 = sha256 == null ? "" : sha256;
        return this;
    }

    public boolean isHashPartial() {
        return hashPartial;
    }

    public FileAnalysis setHashPartial(boolean hashPartial) {
        this.hashPartial = hashPartial;
        return this;
    }

    public double entropy() {
        return entropy;
    }

    public FileAnalysis setEntropy(double entropy) {
        this.entropy = entropy;
        return this;
    }

    public PeInfo peInfo() {
        return peInfo;
    }

    public FileAnalysis setPeInfo(PeInfo peInfo) {
        this.peInfo = peInfo;
        return this;
    }

    public SignatureInfo signatureInfo() {
        return signatureInfo;
    }

    public FileAnalysis setSignatureInfo(SignatureInfo signatureInfo) {
        this.signatureInfo = signatureInfo == null ? SignatureInfo.unsigned() : signatureInfo;
        return this;
    }

    public Set<String> stringIndicatorCodes() {
        return stringIndicatorCodes;
    }

    public Set<String> stringIndicatorLabels() {
        return stringIndicatorLabels;
    }

    public List<RuleMatch> ruleMatches() {
        return ruleMatches;
    }

    public List<RiskFactor> engineFactors() {
        return engineFactors;
    }

    public String reputationLabel() {
        return reputationLabel;
    }

    public FileAnalysis setReputationLabel(String reputationLabel) {
        this.reputationLabel = reputationLabel == null ? "" : reputationLabel;
        return this;
    }

    public Severity reputationSeverity() {
        return reputationSeverity;
    }

    public FileAnalysis setReputationSeverity(Severity reputationSeverity) {
        this.reputationSeverity = reputationSeverity == null ? Severity.INFO : reputationSeverity;
        return this;
    }

    public boolean isFromArchive() {
        return fromArchive;
    }

    public FileAnalysis setFromArchive(boolean fromArchive) {
        this.fromArchive = fromArchive;
        return this;
    }

    public Path archivePath() {
        return archivePath;
    }

    public FileAnalysis setArchivePath(Path archivePath) {
        this.archivePath = archivePath;
        return this;
    }

    public String archiveEntry() {
        return archiveEntry;
    }

    public FileAnalysis setArchiveEntry(String archiveEntry) {
        this.archiveEntry = archiveEntry;
        return this;
    }

    public BehavioralContext behavior() {
        return behavior;
    }

    public FileAnalysis setBehavior(BehavioralContext behavior) {
        this.behavior = behavior == null ? new BehavioralContext() : behavior;
        return this;
    }

    public boolean isAnalysisError() {
        return analysisError;
    }

    public String analysisErrorDetail() {
        return analysisErrorDetail;
    }

    public FileAnalysis setAnalysisError(String detail) {
        this.analysisError = true;
        this.analysisErrorDetail = detail == null ? "" : detail;
        return this;
    }

    public boolean hasStringIndicator(String code) {
        return stringIndicatorCodes.contains(code);
    }
}
