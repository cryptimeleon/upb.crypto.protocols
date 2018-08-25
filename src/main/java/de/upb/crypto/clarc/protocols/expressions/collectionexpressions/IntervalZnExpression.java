package de.upb.crypto.clarc.protocols.expressions.collectionexpressions;

import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.math.BigInteger;
import java.util.Objects;

public class IntervalZnExpression implements CollectionExpression {

    @Represented
    private BigInteger lowerBound;
    @Represented
    private BigInteger upperBound;

    public IntervalZnExpression(BigInteger lowerBound, BigInteger upperBound) {
        this.lowerBound = lowerBound;
        this.upperBound = upperBound;
    }

    public IntervalZnExpression(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public BigInteger getLowerBound() {
        return lowerBound;
    }

    public void setLowerBound(BigInteger lowerBound) {
        this.lowerBound = lowerBound;
    }

    public BigInteger getUpperBound() {
        return upperBound;
    }

    public void setUpperBound(BigInteger upperBound) {
        this.upperBound = upperBound;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        accumulator.escapeAndSeparate("[".getBytes());
        accumulator.escapeAndSeparate(getLowerBound().toByteArray());
        accumulator.escapeAndSeparate(getUpperBound().toByteArray());
        accumulator.escapeAndSeparate("]".getBytes());
        return accumulator;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IntervalZnExpression that = (IntervalZnExpression) o;
        return Objects.equals(getLowerBound(), that.getLowerBound()) &&
                Objects.equals(getUpperBound(), that.getUpperBound());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getLowerBound(), getUpperBound());
    }

    @Override
    public String toString() {
        return "[" + getLowerBound().toString() + " , " + getUpperBound().toString() + "]";
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }
}
