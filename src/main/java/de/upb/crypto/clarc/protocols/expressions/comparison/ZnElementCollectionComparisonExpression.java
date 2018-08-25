package de.upb.crypto.clarc.protocols.expressions.comparison;

import de.upb.crypto.clarc.protocols.expressions.arith.ArithExpression;
import de.upb.crypto.clarc.protocols.expressions.collectionexpressions.CollectionExpression;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;

/**
 * A general expression for an arithmetic expressions, indicating an expressions relation to a collection (e.g. a
 * set, a sequence or an interval).
 * Giving some policy facts (especially GroupElementPolicyFacts and ZnElementPolicyFacts), the expression
 * can be checked for fulfillment (true or false)
 */
public interface ZnElementCollectionComparisonExpression extends CollectionComparisonExpression {


    EquationPrimitives getComparator();

    /**
     * @return the Left-hand-side of the expression
     */
    ArithExpression getLHS();

    /**
     * @return the collection expression
     */
    CollectionExpression getCollection();


    /**
     * Updates the ByteAccumulator with the bytes from this class. The input to the accumulators update function
     * should be an injective (with respect to a given domain) byte encoding of this object.
     *
     * @param accumulator used for generation of UniqueByteRepresentation
     */
    @Override
    default ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        accumulator.escapeAndSeparate(getComparator().getCharForElement(getComparator()).getBytes());
        accumulator.escapeAndSeparate(getLHS());
        accumulator.escapeAndAppend(getCollection());
        return accumulator;
    }
}
