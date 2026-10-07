package com.ratshield.core;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Behavioural signals observed by the monitors for a given file or process. Signals are
 * accumulated over time and combined with static analysis by the detection engine so that
 * a single weak indicator (for example "unsigned") never produces a confident verdict on
 * its own.
 */
public final class BehavioralContext {
    private final Set<String> tags = new LinkedHashSet<>();
    private boolean recentlyDownloaded;
    private long downloadAgeSeconds = -1;
    private boolean inTemp;
    private boolean inAppData;
    private boolean inStartupLocation;
    private boolean spawnedShellChild;
    private boolean spawnedEncodedShell;
    private boolean persistenceCreated;
    private boolean suspiciousOutboundConnection;
    private boolean longLivedExternalConnection;
    private boolean processInjection;
    private boolean credentialAccess;
    private boolean defenseEvasion;
    private boolean securityToolTampering;
    private boolean newProcessWithNetwork;
    private int suspiciousChildCount;
    private int parentRiskScore;
    private String parentProcess;

    public Set<String> tags() {
        return Collections.unmodifiableSet(tags);
    }

    public BehavioralContext tag(String tag) {
        if (tag != null && !tag.isBlank()) {
            tags.add(tag);
        }
        return this;
    }

    public BehavioralContext tags(Set<String> values) {
        if (values != null) {
            tags.addAll(values);
        }
        return this;
    }

    public boolean hasTag(String tag) {
        return tags.contains(tag);
    }

    public boolean isRecentlyDownloaded() {
        return recentlyDownloaded;
    }

    public BehavioralContext setRecentlyDownloaded(boolean value, long ageSeconds) {
        this.recentlyDownloaded = value;
        this.downloadAgeSeconds = ageSeconds;
        if (value) {
            tag("recently_downloaded");
        }
        return this;
    }

    public long downloadAgeSeconds() {
        return downloadAgeSeconds;
    }

    public boolean isInTemp() {
        return inTemp;
    }

    public BehavioralContext setInTemp(boolean value) {
        this.inTemp = value;
        if (value) {
            tag("in_temp");
        }
        return this;
    }

    public boolean isInAppData() {
        return inAppData;
    }

    public BehavioralContext setInAppData(boolean value) {
        this.inAppData = value;
        if (value) {
            tag("in_appdata");
        }
        return this;
    }

    public boolean isInStartupLocation() {
        return inStartupLocation;
    }

    public BehavioralContext setInStartupLocation(boolean value) {
        this.inStartupLocation = value;
        if (value) {
            tag("in_startup");
        }
        return this;
    }

    public boolean isSpawnedShellChild() {
        return spawnedShellChild;
    }

    public BehavioralContext setSpawnedShellChild(boolean value) {
        this.spawnedShellChild = value;
        if (value) {
            tag("spawned_shell");
        }
        return this;
    }

    public boolean isSpawnedEncodedShell() {
        return spawnedEncodedShell;
    }

    public BehavioralContext setSpawnedEncodedShell(boolean value) {
        this.spawnedEncodedShell = value;
        if (value) {
            tag("encoded_command");
        }
        return this;
    }

    public boolean isPersistenceCreated() {
        return persistenceCreated;
    }

    public BehavioralContext setPersistenceCreated(boolean value) {
        this.persistenceCreated = value;
        if (value) {
            tag("persistence_created");
        }
        return this;
    }

    public boolean isSuspiciousOutboundConnection() {
        return suspiciousOutboundConnection;
    }

    public BehavioralContext setSuspiciousOutboundConnection(boolean value) {
        this.suspiciousOutboundConnection = value;
        if (value) {
            tag("suspicious_connection");
        }
        return this;
    }

    public boolean isLongLivedExternalConnection() {
        return longLivedExternalConnection;
    }

    public BehavioralContext setLongLivedExternalConnection(boolean value) {
        this.longLivedExternalConnection = value;
        if (value) {
            tag("long_lived_connection");
        }
        return this;
    }

    public boolean isProcessInjection() {
        return processInjection;
    }

    public BehavioralContext setProcessInjection(boolean value) {
        this.processInjection = value;
        if (value) {
            tag("process_injection");
        }
        return this;
    }

    public boolean isCredentialAccess() {
        return credentialAccess;
    }

    public BehavioralContext setCredentialAccess(boolean value) {
        this.credentialAccess = value;
        if (value) {
            tag("credential_access");
        }
        return this;
    }

    public boolean isDefenseEvasion() {
        return defenseEvasion;
    }

    public BehavioralContext setDefenseEvasion(boolean value) {
        this.defenseEvasion = value;
        if (value) {
            tag("defense_evasion");
        }
        return this;
    }

    public boolean isSecurityToolTampering() {
        return securityToolTampering;
    }

    public BehavioralContext setSecurityToolTampering(boolean value) {
        this.securityToolTampering = value;
        if (value) {
            tag("security_tampering");
        }
        return this;
    }

    public boolean isNewProcessWithNetwork() {
        return newProcessWithNetwork;
    }

    public BehavioralContext setNewProcessWithNetwork(boolean value) {
        this.newProcessWithNetwork = value;
        if (value) {
            tag("new_process_network");
        }
        return this;
    }

    public int suspiciousChildCount() {
        return suspiciousChildCount;
    }

    public BehavioralContext setSuspiciousChildCount(int value) {
        this.suspiciousChildCount = value;
        return this;
    }

    public int parentRiskScore() {
        return parentRiskScore;
    }

    public String parentProcess() {
        return parentProcess;
    }

    public BehavioralContext setParent(String process, int riskScore) {
        this.parentProcess = process;
        this.parentRiskScore = riskScore;
        if (riskScore >= 40) {
            tag("suspicious_parent");
        }
        return this;
    }

    public boolean isEmpty() {
        return tags.isEmpty() && !recentlyDownloaded && !inTemp && !inAppData;
    }
}
