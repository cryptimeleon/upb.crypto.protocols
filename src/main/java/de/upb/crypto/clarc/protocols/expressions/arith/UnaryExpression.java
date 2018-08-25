package de.upb.crypto.clarc.protocols.expressions.arith;

import de.upb.crypto.math.interfaces.hash.ByteAccumulator;

import java.util.Set;

abstract class UnaryExpression implements ArithExpression {

    protected abstract ArithExpression getElement();

    /**
     * @return the operand of the expression
     */
    protected abstract String getOp();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        UnaryExpression that = (UnaryExpression) o;

        return getElement() != null ? getElement().equals(that.getElement()) : that.getElement() == null;
    }

    @Override
    public int hashCode() {
        int result = getElement() != null ? getElement().hashCode() : 0;
        result = 31 * result + this.getClass().getCanonicalName().hashCode();
        return result;
    }

    @Override
    public boolean isDetermined() {
        return getElement().isDetermined();
    }

    @Override
    public void getVariables(Set<Variable> result) {
        getElement().getVariables(result);
    }

    /**
     * Updates the ByteAccumulator with the bytes from this class. The input to the accumulators update function
     * should be an injective (with respect to a given domain) byte encoding of this object.
     *
     * @param accumulator the accumulator used
     */
    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        accumulator.escapeAndSeparate(getOp().getBytes());
        accumulator.escapeAndAppend(this.getElement());
        return accumulator;
    }

    @Override
    public String toString() {
        return "(" +
                getOp() + " " +
                getElement().toString() +
                ")";
    }
}
