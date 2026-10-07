package com.ratshield.core;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public record RiskFactor(String code, String label, int points, Severity severity) {
    public RiskFactor {
        if (severity == null) {
            severity = Severity.INFO;
        }
    }
}
