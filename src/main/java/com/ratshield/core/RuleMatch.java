package com.ratshield.core;

import com.ratshield.core.rules.Rule;

import java.util.Set;

public record RuleMatch(Rule rule, Set<String> matchedStringIds, String matchType) {
}
