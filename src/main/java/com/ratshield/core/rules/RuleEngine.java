package com.ratshield.core.rules;

import com.ratshield.core.RuleMatch;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class RuleEngine {
    public static final int MAX_CONTENT_BYTES = 8 * 1024 * 1024;

    private final List<Rule> rules;
    private final List<String> loadErrors;

    public RuleEngine(List<Rule> rules, List<String> loadErrors) {
        this.rules = List.copyOf(rules);
        this.loadErrors = List.copyOf(loadErrors);
    }

    public List<Rule> rules() {
        return rules;
    }

    public List<String> loadErrors() {
        return loadErrors;
    }

    public int ruleCount() {
        return rules.size();
    }

    public List<RuleMatch> evaluate(byte[] content, long fileSize, String sha256) {
        List<RuleMatch> matches = new ArrayList<>();
        if (content == null || content.length == 0) {
            if (sha256 != null) {
                for (Rule rule : rules) {
                    if (rule.expectedHash().equals(sha256)) {
                        matches.add(new RuleMatch(rule, Set.of(), "hash"));
                    }
                }
            }
            return matches;
        }
        String haystack = new String(content, 0, Math.min(content.length, MAX_CONTENT_BYTES),
                StandardCharsets.ISO_8859_1);
        String lowerHash = sha256 == null ? "" : sha256.toLowerCase(Locale.ROOT);
        for (Rule rule : rules) {
            if (!rule.expectedHash().isEmpty() && rule.expectedHash().equals(lowerHash)) {
                matches.add(new RuleMatch(rule, Set.of(), "hash"));
                continue;
            }
            if (rule.strings().isEmpty()) {
                continue;
            }
            Set<String> matchedIds = new LinkedHashSet<>();
            for (RuleString rs : rule.strings()) {
                if (rs.matches(haystack)) {
                    matchedIds.add(rs.id());
                }
            }
            if (matchedIds.isEmpty() && !rule.condition().referencesStrings()) {
                matchedIds = Set.of();
            }
            if (rule.condition().evaluate(matchedIds, fileSize, rule.stringIds())) {
                matches.add(new RuleMatch(rule, matchedIds, "pattern"));
            }
        }
        return matches;
    }

    public static RuleEngine load(InputStream... streams) {
        List<Rule> rules = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        YaraParser parser = new YaraParser();
        for (InputStream stream : streams) {
            if (stream == null) {
                continue;
            }
            try (stream) {
                String text = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
                rules.addAll(parser.parse(text));
            } catch (IOException e) {
                errors.add("failed to read rule source: " + e.getMessage());
            }
        }
        errors.addAll(parser.errors());
        return new RuleEngine(rules, errors);
    }

    public static RuleEngine loadDefaults() {
        List<InputStream> streams = new ArrayList<>();
        for (String resource : List.of("rules/core.rules", "rules/rat.behavior.rules", "rules/packaging.rules")) {
            InputStream in = RuleEngine.class.getClassLoader().getResourceAsStream(resource);
            if (in != null) {
                streams.add(in);
            }
        }
        return load(streams.toArray(InputStream[]::new));
    }

    public static RuleEngine loadWithUserRules(Path userRuleDir, RuleEngine defaults) {
        List<Rule> rules = new ArrayList<>(defaults.rules());
        List<String> errors = new ArrayList<>(defaults.loadErrors());
        if (userRuleDir != null && Files.isDirectory(userRuleDir)) {
            try (var stream = Files.list(userRuleDir)) {
                stream.filter(p -> p.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".rules"))
                        .sorted().forEach(p -> {
                            try {
                                RuleEngine extra = load(Files.newInputStream(p));
                                rules.addAll(extra.rules());
                                errors.addAll(extra.loadErrors());
                            } catch (IOException e) {
                                errors.add("failed to read " + p + ": " + e.getMessage());
                            }
                        });
            } catch (IOException e) {
                errors.add("failed to enumerate rule directory: " + e.getMessage());
            }
        }
        return new RuleEngine(rules, errors);
    }
}
