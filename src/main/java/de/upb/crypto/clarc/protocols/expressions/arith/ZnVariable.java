package de.upb.crypto.clarc.protocols.expressions.arith;

import de.upb.crypto.clarc.protocols.expressions.GroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.ZnElementPolicyFacts;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StringRepresentation;
import de.upb.crypto.math.structures.zn.Zn;

import java.util.Set;

public class ZnVariable implements ArithZnElementExpression, Variable {

    private final String name;

    public ZnVariable(String name) {
        this.name = name;
    }

    public ZnVariable(Representation representation) {
        this.name = representation.obj().get("name").str().get();
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public Zn.ZnElement calculateResult(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts) {
        if (znFacts.getFacts().containsKey(name)) {
            return znFacts.getFacts().get(name);
        } else {
            throw new IllegalArgumentException(name + " has no value");
        }
    }

    @Override
    public boolean isDetermined() {
        return false;
    }

    @Override
    public void getVariables(Set<Variable> result) {
        result.add(this);
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("name", new StringRepresentation(name));
        return repr;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ZnVariable that = (ZnVariable) o;

        if (getName() != null ? !getName().equals(that.getName()) : that.getName() != null) return false;
        return true;
    }

    @Override
    public int hashCode() {
        int result = getName() != null ? getName().hashCode() : 0;
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
        accumulator.escapeAndAppend(this.name.getBytes());
        return accumulator;
    }

    @Override
    public String toString() {
        return name;
    }
}
