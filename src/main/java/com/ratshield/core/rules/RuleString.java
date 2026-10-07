package com.ratshield.core.rules;

import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * A single compiled pattern from a detection rule. Patterns are evaluated against a latin-1
 * view of the file content so that byte-oriented rules (including {@code wide} UTF-16LE
 * variants) can be expressed with regular expressions without materialising copies of the file.
 */
public final class RuleString {
    private static final String WORD = "A-Za-z0-9_";

    private final String id;
    private final Pattern pattern;

    private RuleString(String id, Pattern pattern) {
        this.id = id;
        this.pattern = pattern;
    }

    public static RuleString text(String id, String text, boolean nocase, boolean wide, boolean fullword) {
        int flags = nocase ? Pattern.CASE_INSENSITIVE : 0;
        String body;
        if (wide) {
            body = hexEscape(text.getBytes(StandardCharsets.UTF_16LE));
            if (fullword) {
                String wordClass = "[\\x41-\\x5a\\x61-\\x7a\\x30-\\x39\\x5f]";
                body = "(?<!" + wordClass + "\\x00)" + body + "(?!" + wordClass + "\\x00)";
            }
        } else {
            body = Pattern.quote(text);
            if (fullword) {
                body = "(?<![" + WORD + "])" + body + "(?![" + WORD + "])";
            }
        }
        return new RuleString(id, Pattern.compile(body, flags));
    }

    public static RuleString hex(String id, String hexBody) {
        return new RuleString(id, Pattern.compile(hexToRegex(hexBody)));
    }

    public static RuleString regex(String id, String regex, boolean nocase) {
        int flags = Pattern.MULTILINE | Pattern.DOTALL | (nocase ? Pattern.CASE_INSENSITIVE : 0);
        Pattern p;
        try {
            p = Pattern.compile(regex, flags);
        } catch (RuntimeException e) {
            p = Pattern.compile(Pattern.quote(regex));
        }
        return new RuleString(id, p);
    }

    public String id() {
        return id;
    }

    public boolean matches(String latinHaystack) {
        return pattern != null && latinHaystack != null && pattern.matcher(latinHaystack).find();
    }

    static String hexEscape(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 4);
        for (byte b : bytes) {
            sb.append(String.format("\\x%02x", b & 0xFF));
        }
        return sb.toString();
    }

    static String hexToRegex(String hexBody) {
        StringBuilder sb = new StringBuilder();
        String body = hexBody.replaceAll("[{}\\s]", "");
        int i = 0;
        while (i < body.length()) {
            char c = body.charAt(i);
            if (c == '[') {
                int end = body.indexOf(']', i);
                if (end < 0) {
                    break;
                }
                String jump = body.substring(i + 1, end);
                String[] parts = jump.split("-");
                if (parts.length == 2) {
                    sb.append(".{").append(parts[0].trim()).append(',').append(parts[1].trim()).append('}');
                } else if (parts.length == 1 && !parts[0].isBlank()) {
                    sb.append(".{").append(parts[0].trim()).append('}');
                }
                i = end + 1;
                continue;
            }
            if (c == '-' || c == '~' || c == '!') {
                i++;
                continue;
            }
            if (i + 1 >= body.length()) {
                break;
            }
            appendByte(sb, body.charAt(i), body.charAt(i + 1));
            i += 2;
        }
        if (sb.isEmpty()) {
            sb.append("(?!)");
        }
        return sb.toString();
    }

    private static void appendByte(StringBuilder sb, char hi, char lo) {
        boolean hiWild = hi == '?';
        boolean loWild = lo == '?';
        int hiVal = Character.digit(hi, 16);
        int loVal = Character.digit(lo, 16);
        if ((!hiWild && hiVal < 0) || (!loWild && loVal < 0)) {
            return;
        }
        if (!hiWild && !loWild) {
            sb.append(String.format("\\x%02x", (hiVal << 4) | loVal));
        } else if (!hiWild) {
            int base = hiVal << 4;
            sb.append(String.format("[\\x%02x-\\x%02x]", base, base | 0x0F));
        } else if (!loWild) {
            sb.append('[');
            for (int n = 0; n < 16; n++) {
                sb.append(String.format("\\x%02x", (n << 4) | loVal));
            }
            sb.append(']');
        } else {
            sb.append("[\\x00-\\xff]");
        }
    }

    @Override
    public String toString() {
        return id;
    }
}
