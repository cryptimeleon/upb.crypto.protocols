package de.upb.crypto.clarc.protocols.expressions.comparison;

import de.upb.crypto.clarc.protocols.expressions.arith.Variable;
import de.upb.crypto.craco.interfaces.policy.PolicyFact;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.util.Collection;
import java.util.Set;

/**
 * An expression that can be used to represent an comparison expression, that is always fulfilled.
 */
public class TautologyExpression implements ComparisonExpression {

    public static int FIXED_HASH_CODE = 178067;

    @Override
    public boolean isFulfilled(Collection<? extends PolicyFact> collection) {
        return true;
    }

    public TautologyExpression() {
    }

    public TautologyExpression(Representation representation) {
    }

    @Override
    public void getVariables(Set<Variable> result) {
        //Nothing to do
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof TautologyExpression;
    }

    @Override
    public int hashCode() {
        return FIXED_HASH_CODE;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        byteAccumulator.escapeAndAppend(this.getClass().getCanonicalName().getBytes());
        return byteAccumulator;
    }

    @Override
    public Representation getRepresentation() {
        return new ObjectRepresentation();
    }
}
