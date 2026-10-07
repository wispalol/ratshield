package com.ratshield.core;

public enum Severity {
    INFO(0),
    LOW(1),
    MEDIUM(2),
    HIGH(3),
    CRITICAL(4);

    private final int rank;

    Severity(int rank) {
        this.rank = rank;
    }

    public int rank() {
        return rank;
    }

    public Severity max(Severity other) {
        return other == null || other.rank <= rank ? this : other;
    }

    public static Severity fromScore(int score) {
        if (score >= 80) return CRITICAL;
        if (score >= 60) return HIGH;
        if (score >= 40) return MEDIUM;
        if (score >= 20) return LOW;
        return INFO;
    }
}
