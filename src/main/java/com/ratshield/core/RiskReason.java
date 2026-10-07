package com.ratshield.core;

import java.util.Objects;

public record RiskReason(String code, String label, int points) {
    public RiskReason {
        Objects.requireNonNull(code, "code");
        Objects.requireNonNull(label, "label");
    }
}
