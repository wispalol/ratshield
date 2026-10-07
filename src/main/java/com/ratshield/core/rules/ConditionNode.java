package com.ratshield.core.rules;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public final class ConditionNode {
    private enum Type {AND, OR, NOT, OF, SIZE, STRING_REF, TRUE, FALSE}

    private final Type type;
    private final List<ConditionNode> children;
    private final String stringId;
    private final String operator;
    private final long operand;
    private final int count;
    private final boolean allSelector;
    private final List<String> ofIds;

    private ConditionNode(Type type, List<ConditionNode> children, String stringId, String operator,
                          long operand, int count, boolean allSelector, List<String> ofIds) {
        this.type = type;
        this.children = children == null ? List.of() : List.copyOf(children);
        this.stringId = stringId;
        this.operator = operator;
        this.operand = operand;
        this.count = count;
        this.allSelector = allSelector;
        this.ofIds = ofIds == null ? List.of() : List.copyOf(ofIds);
    }

    static ConditionNode and(List<ConditionNode> nodes) {
        return new ConditionNode(Type.AND, nodes, null, null, 0, 0, false, null);
    }

    static ConditionNode or(List<ConditionNode> nodes) {
        return new ConditionNode(Type.OR, nodes, null, null, 0, 0, false, null);
    }

    static ConditionNode not(ConditionNode node) {
        return new ConditionNode(Type.NOT, List.of(node), null, null, 0, 0, false, null);
    }

    static ConditionNode of(int count, boolean all, List<String> ids) {
        return new ConditionNode(Type.OF, null, null, null, 0, count, all, ids);
    }

    static ConditionNode sizeCompare(String operator, long bytes) {
        return new ConditionNode(Type.SIZE, null, null, operator, bytes, 0, false, null);
    }

    static ConditionNode stringRef(String id) {
        return new ConditionNode(Type.STRING_REF, null, id, null, 0, 0, false, null);
    }

    static ConditionNode bool(boolean value) {
        return new ConditionNode(value ? Type.TRUE : Type.FALSE, null, null, null, 0, 0, false, null);
    }

    public boolean evaluate(Set<String> matchedIds, long fileSize, Set<String> ruleStringIds) {
        return switch (type) {
            case TRUE -> true;
            case FALSE -> false;
            case AND -> {
                for (ConditionNode child : children) {
                    if (!child.evaluate(matchedIds, fileSize, ruleStringIds)) {
                        yield false;
                    }
                }
                yield true;
            }
            case OR -> {
                for (ConditionNode child : children) {
                    if (child.evaluate(matchedIds, fileSize, ruleStringIds)) {
                        yield true;
                    }
                }
                yield false;
            }
            case NOT -> !children.getFirst().evaluate(matchedIds, fileSize, ruleStringIds);
            case STRING_REF -> matchedIds.contains(stringId);
            case OF -> {
                List<String> candidates = new ArrayList<>();
                for (String id : ruleStringIds) {
                    if (ofIds.isEmpty()) {
                        candidates.add(id);
                        continue;
                    }
                    for (String selector : ofIds) {
                        if (selector.endsWith("*")) {
                            if (id.startsWith(selector.substring(0, selector.length() - 1))) {
                                candidates.add(id);
                            }
                        } else if (id.equals(selector)) {
                            candidates.add(id);
                        }
                    }
                }
                if (candidates.isEmpty()) {
                    yield false;
                }
                int matchedCount = 0;
                for (String id : candidates) {
                    if (matchedIds.contains(id)) {
                        matchedCount++;
                    }
                }
                if (allSelector) {
                    yield matchedCount == candidates.size();
                }
                if (count <= 0) {
                    yield matchedCount > 0;
                }
                yield matchedCount >= count;
            }
            case SIZE -> switch (operator) {
                case "<" -> fileSize < operand;
                case ">" -> fileSize > operand;
                case "<=" -> fileSize <= operand;
                case ">=" -> fileSize >= operand;
                case "==" -> fileSize == operand;
                default -> false;
            };
        };
    }

    public boolean referencesStrings() {
        return switch (type) {
            case STRING_REF, OF -> true;
            case AND, OR, NOT -> {
                for (ConditionNode c : children) {
                    if (c.referencesStrings()) {
                        yield true;
                    }
                }
                yield false;
            }
            default -> false;
        };
    }
}
