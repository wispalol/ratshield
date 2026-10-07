package com.ratshield.core;

public enum RiskLevel {
    SAFE(0, 19),
    LOW(20, 39),
    SUSPICIOUS(40, 59),
    HIGH(60, 79),
    MALWARE(80, 100);

    private final int min;
    private final int max;

    RiskLevel(int min, int max) {
        this.min = min;
        this.max = max;
    }

    public int min() {
        return min;
    }

    public int max() {
        return max;
    }

    public static RiskLevel fromScore(int score) {
        int s = Math.clamp(score, 0, 100);
        if (s >= MALWARE.min) return MALWARE;
        if (s >= HIGH.min) return HIGH;
        if (s >= SUSPICIOUS.min) return SUSPICIOUS;
        if (s >= LOW.min) return LOW;
        return SAFE;
    }
}
