package de.upb.crypto.clarc.protocols.expressions.comparison;

import de.upb.crypto.clarc.protocols.expressions.arith.ArithExpression;
import de.upb.crypto.clarc.protocols.expressions.arith.ArithZnElementExpression;
import de.upb.crypto.clarc.protocols.expressions.arith.Variable;
import de.upb.crypto.clarc.protocols.expressions.collectionexpressions.CollectionExpression;
import de.upb.crypto.clarc.protocols.expressions.collectionexpressions.IntervalZnExpression;
import de.upb.crypto.craco.interfaces.policy.PolicyFact;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.math.BigInteger;
import java.util.Collection;
import java.util.Objects;
import java.util.Set;

public class ZnElementInCollectionComparisonExpression implements ZnElementCollectionComparisonExpression {


    @Represented
    ArithZnElementExpression lhs;
    @Represented
    IntervalZnExpression interval;

    public ZnElementInCollectionComparisonExpression(ArithZnElementExpression lhs, IntervalZnExpression interval) {
        this.lhs = lhs;
        this.interval = interval;
    }

    public ZnElementInCollectionComparisonExpression(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    @Override
    public EquationPrimitives getComparator() {
        return EquationPrimitives.IN_INTERVAL;
    }

    /**
     * @return the Left-hand-side of the expression
     */
    @Override
    public ArithExpression getLHS() {
        return lhs;
    }

    @Override
    public void getVariables(Set<Variable> result) {
        lhs.getVariables(result);
    }

    /**
     * @return the collection expression
     */
    @Override
    public CollectionExpression getCollection() {
        return interval;
    }

    @Override
    public boolean isFulfilled(Collection<? extends PolicyFact> collection) {

        BigInteger valueOfLHS = lhs.calculateResult(this.getGroupFacts(collection), this.getZnFacts(collection))
                .getInteger();
        //Check if lower bound is not greater than current value
        boolean isNotSmallerThanLowerBound = !(interval.getLowerBound().compareTo(valueOfLHS) > 0);
        //Check if upper bound is not smaller than current value
        boolean isNotGreaterThanUpperBound = !(interval.getUpperBound().compareTo(valueOfLHS) < 0);
        return isNotGreaterThanUpperBound && isNotSmallerThanLowerBound;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ZnElementInCollectionComparisonExpression that = (ZnElementInCollectionComparisonExpression) o;
        return Objects.equals(lhs, that.lhs) &&
                Objects.equals(interval, that.interval);
    }

    @Override
    public int hashCode() {

        return Objects.hash(lhs, interval);
    }
}
