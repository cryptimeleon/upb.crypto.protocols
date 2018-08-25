package de.upb.crypto.clarc.protocols.expressions.arith;

import de.upb.crypto.clarc.protocols.expressions.GroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.ZnElementPolicyFacts;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.interfaces.structures.GroupElementMixedExpression;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StringRepresentation;

import java.util.Set;

public class GroupElementVariable implements ArithGroupElementExpression, Variable {

    @UniqueByteRepresented
    private final String name;

    public GroupElementVariable(String name) {
        this.name = name;
    }

    public GroupElementVariable(Representation representation) {
        name = representation.obj().get("name").str().get();
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public GroupElementMixedExpression resultAsEfficientExpression(GroupElementPolicyFacts groupFacts,
                                                                   ZnElementPolicyFacts znFacts) {
        return new GroupElementMixedExpression(calculateResult(groupFacts, znFacts).asPowProductExpression());
    }

    @Override
    public GroupElement calculateResult(GroupElementPolicyFacts GroupElement, ZnElementPolicyFacts znFacts) {
        if (GroupElement.getFacts().containsKey(name)) {
            return GroupElement.getFacts().get(name);
        } else {
            throw new IllegalArgumentException("The variable value of the variable '" + name + "' is not defined");
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

        GroupElementVariable that = (GroupElementVariable) o;

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
     * @param accumulator The accumulator used
     */
    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

    @Override
    public String toString() {
        return name;
    }
}
