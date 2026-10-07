package com.ratshield.core.rules;

import com.ratshield.core.Severity;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class Rule {
    private final String name;
    private final Set<String> tags;
    private final Map<String, String> meta;
    private final List<RuleString> strings;
    private final ConditionNode condition;

    public Rule(String name, Set<String> tags, Map<String, String> meta, List<RuleString> strings, ConditionNode condition) {
        this.name = name;
        this.tags = Collections.unmodifiableSet(new LinkedHashSet<>(tags));
        this.meta = Collections.unmodifiableMap(new LinkedHashMap<>(meta));
        this.strings = List.copyOf(strings);
        this.condition = condition;
    }

    public String name() {
        return name;
    }

    public Set<String> tags() {
        return tags;
    }

    public Map<String, String> meta() {
        return meta;
    }

    public List<RuleString> strings() {
        return strings;
    }

    public ConditionNode condition() {
        return condition;
    }

    public String id() {
        return meta.getOrDefault("id", name);
    }

    public String description() {
        return meta.getOrDefault("description", name);
    }

    public String family() {
        return meta.getOrDefault("family", "");
    }

    public Severity severity() {
        String s = meta.getOrDefault("severity", "medium").toLowerCase(Locale.ROOT);
        return switch (s) {
            case "critical" -> Severity.CRITICAL;
            case "high" -> Severity.HIGH;
            case "low" -> Severity.LOW;
            case "info" -> Severity.INFO;
            default -> Severity.MEDIUM;
        };
    }

    public String expectedHash() {
        return meta.getOrDefault("sha256", "").toLowerCase(Locale.ROOT);
    }

    public Set<String> stringIds() {
        Set<String> ids = new LinkedHashSet<>();
        for (RuleString s : strings) {
            ids.add(s.id());
        }
        return ids;
    }

    @Override
    public String toString() {
        return "Rule[" + name + "]";
    }
}
