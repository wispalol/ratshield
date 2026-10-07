package com.ratshield.core.rules;

import com.ratshield.TestSupport;
import com.ratshield.core.RuleMatch;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RuleEngineTest {

    @Test
    void bundledRulesLoadWithoutErrors() {
        RuleEngine engine = RuleEngine.loadDefaults();
        assertTrue(engine.loadErrors().isEmpty(), "load errors: " + engine.loadErrors());
        assertTrue(engine.ruleCount() >= 20, "expected the bundled rule set, got " + engine.ruleCount());
        assertTrue(engine.rules().stream().allMatch(r -> !r.meta().getOrDefault("severity", "").isEmpty()));
        assertTrue(engine.rules().stream().allMatch(r -> r.condition() != null));
    }

    @Test
    void eicarContentMatchesTheTestRule() {
        RuleEngine engine = RuleEngine.loadDefaults();
        byte[] data = TestSupport.eicar();
        List<RuleMatch> matches = engine.evaluate(data, data.length, null);
        assertFalse(matches.isEmpty(), "EICAR must be detected");
        assertTrue(matches.stream().anyMatch(m -> m.rule().name().equals("Test_EICAR")));
        assertTrue(matches.stream().anyMatch(m -> m.matchType().equals("pattern")));
        List<RuleMatch> byHash = engine.evaluate(data, data.length, TestSupport.EICAR_SHA256);
        assertTrue(byHash.stream().anyMatch(m -> m.matchType().equals("hash")));
    }

    @Test
    void eicarHashIsMatchedEvenWithoutContent() {
        RuleEngine engine = RuleEngine.loadDefaults();
        List<RuleMatch> matches = engine.evaluate(new byte[0], 68, TestSupport.EICAR_SHA256);
        assertFalse(matches.isEmpty());
        assertTrue(matches.stream().allMatch(m -> m.matchType().equals("hash")));
    }

    @Test
    void harmlessContentMatchesNothing() {
        RuleEngine engine = RuleEngine.loadDefaults();
        byte[] data = "Shopping list: milk, eggs, bread; call the dentist on Friday.".getBytes();
        List<RuleMatch> matches = engine.evaluate(data, data.length, null);
        assertTrue(matches.isEmpty(), "unexpected matches: " + matches);
    }

    @Test
    void multiConditionRulesNeedEveryGroup() {
        RuleEngine engine = RuleEngine.loadDefaults();
        byte[] onlyHalf = "powershell -EncodedCommand".getBytes();
        assertTrue(engine.evaluate(onlyHalf, onlyHalf.length, null).isEmpty(),
                "one indicator group alone must not fire the rule");
        byte[] bothHalf = "powershell -EncodedCommand -nop -w hidden".getBytes();
        assertFalse(engine.evaluate(bothHalf, bothHalf.length, null).isEmpty());
    }

    @Test
    void parserReportsMalformedRulesInsteadOfThrowing() {
        YaraParser parser = new YaraParser();
        List<Rule> rules = parser.parse("rule Broken { condition: }");
        assertTrue(rules.isEmpty());
        assertFalse(parser.errors().isEmpty());
    }

    @Test
    void parserCapturesTagsMetaAndModifiers() {
        YaraParser parser = new YaraParser();
        List<Rule> rules = parser.parse("""
                rule Sample : tagone tagtwo {
                    meta:
                        description = "a sample rule"
                        severity = "high"
                    strings:
                        $a = "Hello World" nocase
                    condition:
                        $a
                }
                """);
        assertTrue(parser.errors().isEmpty(), parser.errors().toString());
        assertEquals(1, rules.size());
        Rule rule = rules.getFirst();
        assertEquals("Sample", rule.name());
        assertTrue(rule.tags().contains("tagone"));
        assertEquals("a sample rule", rule.meta().get("description"));
        assertEquals("high", rule.meta().get("severity"));
        Set<String> ids = rule.strings().stream().map(RuleString::id).collect(Collectors.toSet());
        assertEquals(Set.of("$a"), ids);
        assertTrue(rule.condition().evaluate(Set.of("$a"), 10, ids));
        assertFalse(rule.condition().evaluate(Set.of(), 10, ids));
    }
}
