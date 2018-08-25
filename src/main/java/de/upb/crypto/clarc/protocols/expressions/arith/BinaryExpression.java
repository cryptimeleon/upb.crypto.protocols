package de.upb.crypto.clarc.protocols.expressions.arith;

import de.upb.crypto.math.interfaces.hash.ByteAccumulator;

import java.util.Set;

public abstract class BinaryExpression implements ArithExpression {

    /**
     * @return the left-hand-site of the expression
     */
    public abstract ArithExpression getLHS();

    /**
     * @return the right-hand-site of the expression
     */
    public abstract ArithExpression getRHS();

    /**
     * @return the operand of the expression
     */
    public abstract String getOp();

    @Override
    public boolean isDetermined() {
        return getLHS().isDetermined() && getRHS().isDetermined();
    }

    @Override
    public void getVariables(Set<Variable> result) {
        getLHS().getVariables(result);
        getRHS().getVariables(result);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        BinaryExpression that = (BinaryExpression) o;

        if (getLHS() != null ? !getLHS().equals(that.getLHS()) : that.getLHS() != null) return false;
        if (getOp() != null ? !getOp().equals(that.getOp()) : that.getOp() != null) return false;
        return getRHS() != null ? getRHS().equals(that.getRHS()) : that.getRHS() == null;
    }

    @Override
    public int hashCode() {
        int result = getLHS() != null ? getLHS().hashCode() : 0;
        result = 31 * result + (getRHS() != null ? getRHS().hashCode() : 0);
        result = 31 * result + this.getClass().getCanonicalName().hashCode();
        return result;
    }

    /**
     * Updates the ByteAccumulator with the bytes from this class. The input to the accumulators update function
     * should be an injective (with respect to a given domain) byte encoding of this object.
     *
     * @param accumulator the used accumulator
     */
    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        accumulator.escapeAndSeparate(getOp().getBytes());
        accumulator.escapeAndSeparate(getLHS());
        accumulator.escapeAndAppend(getRHS());
        return accumulator;
    }

    @Override
    public String toString() {
        return "(" +
                getLHS().toString() + " " +
                getOp() + " " +
                getRHS().toString() +
                ")";
    }
}
