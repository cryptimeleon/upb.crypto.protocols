package de.upb.crypto.clarc.protocols.expressions.comparison;

public enum EquationPrimitives {
    GREATER, GREATER_EQUAL, EQUAL, LESSER_EQUAL, LESSER, NOT_EQUAL, IN_INTERVAL;

    public String getCharForElement(EquationPrimitives comparator) {
        switch (comparator) {
            case GREATER:
                return ">";
            case GREATER_EQUAL:
                return ">=";
            case EQUAL:
                return "=";
            case LESSER_EQUAL:
                return "<=";
            case LESSER:
                return "<";
            case NOT_EQUAL:
                return "<>";
            case IN_INTERVAL:
                return "in";
            default:
                throw new IllegalArgumentException("Element must be contained in enum, " + comparator.toString() + " " +
                        "is not contained");
        }
    }
}
