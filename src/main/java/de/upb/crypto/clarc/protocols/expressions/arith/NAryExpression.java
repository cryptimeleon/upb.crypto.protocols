package de.upb.crypto.clarc.protocols.expressions.arith;

import de.upb.crypto.math.interfaces.hash.ByteAccumulator;

import java.util.List;
import java.util.Set;

public abstract class NAryExpression implements ArithExpression {

    /**
     * @return the operand of the expression
     */
    protected abstract String getOp();

    public abstract boolean addElement(ArithExpression element);

    public abstract boolean removeElement(ArithExpression element);

    protected abstract List<? extends ArithExpression> getElements();

    public abstract void setElements(List<ArithExpression> elements);

    @Override
    public boolean isDetermined() {
        return getElements().stream().allMatch(ArithExpression::isDetermined);
    }

    @Override
    public void getVariables(Set<Variable> result) {
        getElements().stream().sequential().forEach(expr -> expr.getVariables(result));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        NAryExpression that = (NAryExpression) o;
        return getElements() != null ? getElements().equals(that.getElements()) : that.getElements() == null;
    }

    @Override
    public int hashCode() {
        return getElements() != null ? getElements().hashCode() : 0;
    }


    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        accumulator.escapeAndSeparate(getOp().getBytes());
        getElements().forEach(accumulator::escapeAndSeparate);
        return accumulator;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("(");
        builder.append(getOp());
        builder.append("(");
        for (ArithExpression expr : getElements()) {
            builder.append(expr.toString());
            builder.append(", ");
        }

        builder.deleteCharAt(builder.length() - 2);
        builder.append(")");
        builder.append(")");
        return builder.toString();
    }

}
