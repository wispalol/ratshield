package com.ratshield.core.rules;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Parser for a practical subset of the YARA rule language.
 *
 * <p>Supported: rule/tag structure, {@code meta:}, {@code strings:} (text with
 * {@code nocase wide ascii fullword}, hex with {@code ??} nibble wildcards and
 * {@code [n-m]} jumps, and {@code /regex/} with {@code i}) and {@code condition:}
 * expressions built from {@code and}/{@code or}/{@code not}, parentheses,
 * {@code any/all/N of them}, per-string references and {@code filesize} comparisons.</p>
 */
public final class YaraParser {
    public static final class RuleFormatException extends RuntimeException {
        public RuleFormatException(String message) {
            super(message);
        }
    }

    private enum Kind {IDENT, NUMBER, STRING, HEX, REGEX, DOLLAR, SYMBOL, EOF}

    private record Tok(Kind kind, String text, long value) {
    }

    private final List<Tok> tokens = new ArrayList<>();
    private int pos;
    private final List<String> errors = new ArrayList<>();

    public List<String> errors() {
        return errors;
    }

    public List<Rule> parse(String source) {
        List<Rule> rules = new ArrayList<>();
        List<String> chunks = splitRules(source);
        for (String chunk : chunks) {
            if (chunk.isBlank()) {
                continue;
            }
            try {
                Rule rule = parseRule(chunk);
                if (rule != null) {
                    rules.add(rule);
                }
            } catch (RuntimeException e) {
                errors.add(e.getMessage());
            }
        }
        return rules;
    }

    private static List<String> splitRules(String source) {
        List<String> chunks = new ArrayList<>();
        int depth = 0;
        StringBuilder current = new StringBuilder();
        boolean inString = false;
        boolean inComment = false;
        for (int i = 0; i < source.length(); i++) {
            char c = source.charAt(i);
            if (inComment) {
                current.append(c);
                if (c == '\n') {
                    inComment = false;
                }
                continue;
            }
            if (inString) {
                current.append(c);
                if (c == '\\' && i + 1 < source.length()) {
                    current.append(source.charAt(++i));
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (c == '/' && i + 1 < source.length() && source.charAt(i + 1) == '/') {
                inComment = true;
                current.append(c);
                continue;
            }
            if (c == '/' && i + 1 < source.length() && source.charAt(i + 1) == '*') {
                int end = source.indexOf("*/", i + 2);
                if (end > 0) {
                    current.append(source, i, end + 2);
                    i = end + 1;
                }
                continue;
            }
            if (c == '"') {
                inString = true;
                current.append(c);
                continue;
            }
            if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
            }
            current.append(c);
            if (depth == 0 && current.toString().contains("rule ")) {
                String chunk = current.toString().trim();
                if (endsWithClosedBlock(chunk)) {
                    chunks.add(chunk);
                    current.setLength(0);
                }
            }
        }
        if (!current.toString().isBlank()) {
            chunks.add(current.toString().trim());
        }
        return chunks;
    }

    private static boolean endsWithClosedBlock(String chunk) {
        int depth = 0;
        boolean inString = false;
        boolean inComment = false;
        for (int i = 0; i < chunk.length(); i++) {
            char c = chunk.charAt(i);
            if (inComment) {
                if (c == '\n') {
                    inComment = false;
                }
                continue;
            }
            if (inString) {
                if (c == '\\' && i + 1 < chunk.length()) {
                    i++;
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (c == '/' && i + 1 < chunk.length() && chunk.charAt(i + 1) == '/') {
                inComment = true;
                continue;
            }
            if (c == '/' && i + 1 < chunk.length() && chunk.charAt(i + 1) == '*') {
                int end = chunk.indexOf("*/", i + 2);
                if (end < 0) {
                    return false;
                }
                i = end + 1;
                continue;
            }
            if (c == '"') {
                inString = true;
                continue;
            }
            if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return i == chunk.length() - 1;
                }
                if (depth < 0) {
                    return false;
                }
            }
        }
        return false;
    }

    private Rule parseRule(String source) {
        tokenize(source);
        pos = 0;
        if (peek().kind == Kind.EOF) {
            return null;
        }
        expectIdent("rule");
        String name = consume().text();
        if (!isValidIdentifier(name)) {
            throw new RuleFormatException("invalid rule name: " + name);
        }
        Set<String> tags = new LinkedHashSet<>();
        if (peekIsSymbol(":")) {
            next();
            while (peek().kind == Kind.IDENT) {
                tags.add(consume().text().toLowerCase(Locale.ROOT));
            }
        }
        expectSymbol("{");
        Map<String, String> meta = new LinkedHashMap<>();
        List<RuleString> strings = new ArrayList<>();
        ConditionNode condition = null;
        while (!peekIsSymbol("}")) {
            Tok tok = consume();
            if (tok.kind == Kind.IDENT && tok.text().equals("meta")) {
                expectSymbol(":");
                meta = parseMeta();
            } else if (tok.kind == Kind.IDENT && tok.text().equals("strings")) {
                expectSymbol(":");
                strings = parseStrings();
            } else if (tok.kind == Kind.IDENT && tok.text().equals("condition")) {
                expectSymbol(":");
                condition = parseCondition();
            } else {
                throw new RuleFormatException("unexpected token in rule " + name + ": " + tok.text());
            }
        }
        if (condition == null) {
            throw new RuleFormatException("rule " + name + " has no condition");
        }
        expectSymbol("}");
        if (peek().kind != Kind.EOF) {
            throw new RuleFormatException("unexpected content after rule " + name + ": " + peek().text());
        }
        return new Rule(name, tags, meta, strings, condition);
    }

    private Map<String, String> parseMeta() {
        Map<String, String> meta = new LinkedHashMap<>();
        while (peek().kind == Kind.IDENT && !peekIsSectionKeyword()) {
            String key = consume().text();
            expectSymbol("=");
            Tok value = consume();
            String v = switch (value.kind) {
                case STRING -> value.text();
                case NUMBER -> Long.toString(value.value());
                default -> value.text();
            };
            meta.put(key.toLowerCase(Locale.ROOT), v);
        }
        return meta;
    }

    private boolean peekIsSectionKeyword() {
        Tok t = peek();
        if (t.kind != Kind.IDENT) {
            return false;
        }
        return t.text().equals("strings") || t.text().equals("condition") || t.text().equals("meta");
    }

    private List<RuleString> parseStrings() {
        List<RuleString> strings = new ArrayList<>();
        while (peek().kind == Kind.DOLLAR) {
            String id = consume().text();
            expectSymbol("=");
            Tok value = consume();
            boolean nocase = false;
            boolean wide = false;
            boolean fullword = false;
            if (value.kind == Kind.STRING) {
                while (peek().kind == Kind.IDENT && isModifier(peek().text())) {
                    String mod = consume().text();
                    switch (mod) {
                        case "nocase" -> nocase = true;
                        case "wide" -> wide = true;
                        case "fullword" -> fullword = true;
                        default -> {
                        }
                    }
                }
                strings.add(RuleString.text(id, value.text(), nocase, wide, fullword));
            } else if (value.kind == Kind.HEX) {
                strings.add(RuleString.hex(id, value.text()));
            } else if (value.kind == Kind.REGEX) {
                while (peek().kind == Kind.IDENT && isModifier(peek().text())) {
                    String mod = consume().text();
                    if (mod.equals("nocase") || mod.equals("i")) {
                        nocase = true;
                    }
                }
                strings.add(RuleString.regex(id, value.text(), nocase));
            } else {
                throw new RuleFormatException("unsupported string definition for " + id);
            }
        }
        return strings;
    }

    private static boolean isModifier(String s) {
        return s.equals("nocase") || s.equals("wide") || s.equals("ascii") || s.equals("fullword")
                || s.equals("xor") || s.equals("base64") || s.equals("base64wide") || s.equals("i");
    }

    private ConditionNode parseCondition() {
        ConditionNode node = parseOr();
        return node;
    }

    private ConditionNode parseOr() {
        List<ConditionNode> nodes = new ArrayList<>();
        nodes.add(parseAnd());
        while (peekIsKeyword("or")) {
            next();
            nodes.add(parseAnd());
        }
        return nodes.size() == 1 ? nodes.getFirst() : ConditionNode.or(nodes);
    }

    private ConditionNode parseAnd() {
        List<ConditionNode> nodes = new ArrayList<>();
        nodes.add(parseUnary());
        while (peekIsKeyword("and")) {
            next();
            nodes.add(parseUnary());
        }
        return nodes.size() == 1 ? nodes.getFirst() : ConditionNode.and(nodes);
    }

    private ConditionNode parseUnary() {
        if (peekIsKeyword("not")) {
            next();
            return ConditionNode.not(parseUnary());
        }
        return parsePrimary();
    }

    private ConditionNode parsePrimary() {
        Tok tok = peek();
        if (tok.kind == Kind.SYMBOL && tok.text().equals("(")) {
            next();
            ConditionNode inner = parseOr();
            expectSymbol(")");
            return inner;
        }
        if (tok.kind == Kind.IDENT && tok.text().equals("filesize")) {
            next();
            String op = consume().text();
            long value = parseSizeLiteral();
            return ConditionNode.sizeCompare(op, value);
        }
        if (tok.kind == Kind.IDENT && (tok.text().equals("true") || tok.text().equals("false"))) {
            next();
            return ConditionNode.bool(tok.text().equals("true"));
        }
        if (tok.kind == Kind.IDENT && (tok.text().equals("any") || tok.text().equals("all"))) {
            next();
            return parseOf(tok.text().equals("all") ? -1 : 0, tok.text().equals("all"));
        }
        if (tok.kind == Kind.NUMBER) {
            next();
            if (peekIsKeyword("of")) {
                return parseOf((int) tok.value(), false);
            }
            throw new RuleFormatException("unexpected number in condition: " + tok.text());
        }
        if (tok.kind == Kind.DOLLAR) {
            next();
            if (peekIsKeyword("of")) {
                return parseOf(1, false);
            }
            return ConditionNode.stringRef(tok.text());
        }
        if (tok.kind == Kind.IDENT && tok.text().equals("them")) {
            next();
            return ConditionNode.of(-1, false, List.of());
        }
        throw new RuleFormatException("unsupported condition token: " + tok.text());
    }

    private ConditionNode parseOf(int count, boolean all) {
        expectKeyword("of");
        if (peekIsKeyword("them")) {
            next();
            return ConditionNode.of(count, all, List.of());
        }
        if (peek().kind == Kind.SYMBOL && peek().text().equals("(")) {
            next();
            List<String> ids = new ArrayList<>();
            while (!peekIsSymbol(")")) {
                Tok t = consume();
                if (t.kind == Kind.SYMBOL && t.text().equals(",")) {
                    continue;
                }
                if (t.kind != Kind.DOLLAR) {
                    throw new RuleFormatException("expected string identifier in of-expression");
                }
                ids.add(t.text());
            }
            expectSymbol(")");
            return ConditionNode.of(count, all, ids);
        }
        throw new RuleFormatException("unsupported of-expression");
    }

    private long parseSizeLiteral() {
        Tok num = consume();
        if (num.kind != Kind.NUMBER) {
            throw new RuleFormatException("expected size literal");
        }
        long value = num.value();
        if (peek().kind == Kind.IDENT) {
            String unit = peek().text().toUpperCase(Locale.ROOT);
            if (unit.equals("KB")) {
                next();
                return value * 1024;
            } else if (unit.equals("MB")) {
                next();
                return value * 1024 * 1024;
            } else if (unit.equals("GB")) {
                next();
                return value * 1024 * 1024 * 1024;
            }
        }
        return value;
    }

    private void tokenize(String source) {
        tokens.clear();
        pos = 0;
        int i = 0;
        int n = source.length();
        while (i < n) {
            char c = source.charAt(i);
            if (Character.isWhitespace(c)) {
                i++;
                continue;
            }
            if (c == '/' && i + 1 < n && source.charAt(i + 1) == '/') {
                while (i < n && source.charAt(i) != '\n') {
                    i++;
                }
                continue;
            }
            if (c == '/' && i + 1 < n && source.charAt(i + 1) == '*') {
                int end = source.indexOf("*/", i + 2);
                i = end < 0 ? n : end + 2;
                continue;
            }
            if (c == '"') {
                StringBuilder sb = new StringBuilder();
                i++;
                while (i < n) {
                    char d = source.charAt(i);
                    if (d == '\\' && i + 1 < n) {
                        char e = source.charAt(i + 1);
                        sb.append(switch (e) {
                            case 'n' -> '\n';
                            case 't' -> '\t';
                            case 'r' -> '\r';
                            default -> e;
                        });
                        i += 2;
                        continue;
                    }
                    if (d == '"') {
                        i++;
                        break;
                    }
                    sb.append(d);
                    i++;
                }
                tokens.add(new Tok(Kind.STRING, sb.toString(), 0));
                continue;
            }
            if (c == '/') {
                int close = source.indexOf('/', i + 1);
                int lineEnd = source.indexOf('\n', i + 1);
                if (close > i + 1 && (lineEnd < 0 || close < lineEnd) && looksLikeRegex(source, i + 1, close)) {
                    StringBuilder sb = new StringBuilder();
                    i++;
                    while (i < n) {
                        char d = source.charAt(i);
                        if (d == '\\' && i + 1 < n) {
                            sb.append(d).append(source.charAt(i + 1));
                            i += 2;
                            continue;
                        }
                        if (d == '/') {
                            i++;
                            break;
                        }
                        sb.append(d);
                        i++;
                    }
                    while (i < n && (Character.isLetter(source.charAt(i)) || source.charAt(i) == 'i')) {
                        i++;
                    }
                    tokens.add(new Tok(Kind.REGEX, sb.toString(), 0));
                    continue;
                }
                tokens.add(new Tok(Kind.SYMBOL, "/", 0));
                i++;
                continue;
            }
            if (c == '{') {
                int close = source.indexOf('}', i + 1);
                if (close > i && looksLikeHexBlock(source, i + 1, close)) {
                    tokens.add(new Tok(Kind.HEX, source.substring(i, close + 1), 0));
                    i = close + 1;
                    continue;
                }
                tokens.add(new Tok(Kind.SYMBOL, "{", 0));
                i++;
                continue;
            }
            if (c == '$') {
                StringBuilder sb = new StringBuilder("$");
                i++;
                while (i < n && (Character.isLetterOrDigit(source.charAt(i)) || source.charAt(i) == '_'
                        || source.charAt(i) == '*')) {
                    sb.append(source.charAt(i));
                    i++;
                }
                tokens.add(new Tok(Kind.DOLLAR, sb.toString(), 0));
                continue;
            }
            if (Character.isDigit(c)) {
                int start = i;
                long value = 0;
                boolean hex = false;
                if (c == '0' && i + 1 < n && (source.charAt(i + 1) == 'x' || source.charAt(i + 1) == 'X')) {
                    hex = true;
                    i += 2;
                    while (i < n && Character.digit(source.charAt(i), 16) >= 0) {
                        value = value * 16 + Character.digit(source.charAt(i), 16);
                        i++;
                    }
                } else {
                    while (i < n && Character.isDigit(source.charAt(i))) {
                        value = value * 10 + (source.charAt(i) - '0');
                        i++;
                    }
                }
                tokens.add(new Tok(Kind.NUMBER, source.substring(start, i), value));
                continue;
            }
            if (Character.isLetter(c) || c == '_') {
                int start = i;
                while (i < n && (Character.isLetterOrDigit(source.charAt(i)) || source.charAt(i) == '_'
                        || source.charAt(i) == '.' || source.charAt(i) == '-')) {
                    i++;
                }
                tokens.add(new Tok(Kind.IDENT, source.substring(start, i), 0));
                continue;
            }
            if ("{}()=<>,:*/".indexOf(c) >= 0) {
                if ((c == '<' || c == '>') && i + 1 < n && source.charAt(i + 1) == '=') {
                    tokens.add(new Tok(Kind.SYMBOL, "" + c + "=", 0));
                    i += 2;
                    continue;
                }
                tokens.add(new Tok(Kind.SYMBOL, String.valueOf(c), 0));
                i++;
                continue;
            }
            i++;
        }
        tokens.add(new Tok(Kind.EOF, "<eof>", 0));
    }

    private Tok peek() {
        return tokens.get(Math.min(pos, tokens.size() - 1));
    }

    private Tok next() {
        Tok t = peek();
        if (pos < tokens.size() - 1) {
            pos++;
        }
        return t;
    }

    private Tok consume() {
        Tok t = peek();
        if (t.kind == Kind.EOF) {
            throw new RuleFormatException("unexpected end of rule text");
        }
        pos++;
        return t;
    }

    private boolean peekIsSymbol(String s) {
        Tok t = peek();
        return t.kind == Kind.SYMBOL && t.text().equals(s);
    }

    private boolean peekIsKeyword(String s) {
        Tok t = peek();
        return t.kind == Kind.IDENT && t.text().equals(s);
    }

    private void expectSymbol(String s) {
        Tok t = consume();
        if (t.kind != Kind.SYMBOL || !t.text().equals(s)) {
            throw new RuleFormatException("expected '" + s + "' but found '" + t.text() + "'");
        }
    }

    private void expectKeyword(String s) {
        Tok t = consume();
        if (t.kind != Kind.IDENT || !t.text().equals(s)) {
            throw new RuleFormatException("expected '" + s + "' but found '" + t.text() + "'");
        }
    }

    private void expectIdent(String s) {
        Tok t = consume();
        if (t.kind != Kind.IDENT || !t.text().equals(s)) {
            throw new RuleFormatException("expected '" + s + "'");
        }
    }

    private static boolean looksLikeRegex(String source, int start, int end) {
        if (end <= start) {
            return false;
        }
        char first = source.charAt(start);
        if (Character.isWhitespace(first)) {
            return false;
        }
        return source.substring(start, end).indexOf('\n') < 0;
    }

    private static boolean looksLikeHexBlock(String source, int start, int end) {
        if (end <= start) {
            return false;
        }
        for (int i = start; i < end; i++) {
            char c = source.charAt(i);
            boolean ok = Character.isWhitespace(c) || Character.digit(c, 16) >= 0 || c == '?' || c == '['
                    || c == ']' || c == '-' || c == '~' || c == '!' || c == '{' || c == '}';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    private static boolean isValidIdentifier(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (!Character.isLetterOrDigit(c) && c != '_') {
                return false;
            }
        }
        return true;
    }
}
