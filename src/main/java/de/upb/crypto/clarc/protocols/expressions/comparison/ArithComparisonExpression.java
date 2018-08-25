package de.upb.crypto.clarc.protocols.expressions.comparison;

import de.upb.crypto.clarc.protocols.expressions.arith.ArithExpression;
import de.upb.crypto.clarc.protocols.expressions.arith.Variable;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;

import java.util.Set;

/**
 * A general comparison expression for two Arithmetic expressions.
 * Giving some policy facts (especially GroupElementPolicyFacts and ZnElementPolicyFacts), the comparision expression
 * can be checked for fulfillment (true or false)
 */
public interface ArithComparisonExpression extends ComparisonExpression {


    EquationPrimitives getComparator();

    /**
     * Returns the Left-hand-side of the comparision
     *
     * @return left-hand-site of the comparision expression
     */
    ArithExpression getLHS();

    /**
     * Returns the Right-hand-side of the comparision
     *
     * @return right-hand-site of the comparision expression
     */
    ArithExpression getRHS();


    /**
     * Updates the ByteAccumulator with the bytes from this class. The input to the accumulators update function
     * should be an injective (with respect to a given domain) byte encoding of this object.
     *
     * @param accumulator used for generation of UniqueByteRepresentation
     */
    @Override
    default ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        accumulator.appendAndSeparate(getComparator().getCharForElement(getComparator()).getBytes());
        accumulator.appendAndSeparate(getLHS().getUniqueByteRepresentation());
        accumulator.appendAndSeparate(getRHS().getUniqueByteRepresentation());
        return accumulator;
    }

    @Override
    default void getVariables(Set<Variable> result) {
        getLHS().getVariables(result);
        getRHS().getVariables(result);
    }
}
