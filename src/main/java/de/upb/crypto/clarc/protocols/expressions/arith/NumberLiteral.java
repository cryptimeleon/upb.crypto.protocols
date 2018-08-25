package de.upb.crypto.clarc.protocols.expressions.arith;

import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;

import java.util.Set;

public interface NumberLiteral extends ArithExpression {

    UniqueByteRepresentable getValue();

    /**
     * Updates the ByteAccumulator with the bytes from this class. The input to the accumulators update function
     * should be an injective (with respect to a given domain) byte encoding of this object.
     *
     * @param accumulator the used accumulator
     */
    @Override
    default ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        accumulator.escapeAndAppend(this.getValue());
        return accumulator;
    }

    @Override
    default boolean isDetermined() {
        return true;
    }

    @Override
    default void getVariables(Set<Variable> result) {
        //Nothing to do.
    }
}
