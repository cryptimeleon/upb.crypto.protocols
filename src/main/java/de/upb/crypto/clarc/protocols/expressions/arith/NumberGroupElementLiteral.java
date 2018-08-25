package de.upb.crypto.clarc.protocols.expressions.arith;

import de.upb.crypto.clarc.protocols.expressions.GroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.ZnElementPolicyFacts;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.interfaces.structures.GroupElementMixedExpression;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;

/**
 * This class represents a fixed value from a group, that can not be changed!
 */
public class NumberGroupElementLiteral implements NumberLiteral, ArithGroupElementExpression {

    private final GroupElement value;
    private final Group group;

    public NumberGroupElementLiteral(GroupElement value) {
        this.value = value;
        this.group = value.getStructure();
    }

    public NumberGroupElementLiteral(Representation representation) {
        group = (Group) representation.obj().get("group").repr().recreateRepresentable();
        value = group.getElement(representation.obj().get("value"));
    }

    @Override
    public GroupElementMixedExpression resultAsEfficientExpression(GroupElementPolicyFacts groupFacts,
                                                                   ZnElementPolicyFacts znFacts) {
        return new GroupElementMixedExpression(value.asPowProductExpression());
    }

    @Override
    public GroupElement calculateResult(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts) {
        return value;
    }

    @Override
    public GroupElement getValue() {
        return value;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("value", value.getRepresentation());
        repr.put("group", new RepresentableRepresentation(group));
        return repr;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        NumberGroupElementLiteral that = (NumberGroupElementLiteral) o;

        if (getValue() != null ? !getValue().equals(that.getValue()) : that.getValue() != null) return false;
        return group != null ? group.equals(that.group) : that.group == null;
    }

    @Override
    public int hashCode() {
        int result = getValue() != null ? getValue().hashCode() : 0;
        result = 31 * result + (group != null ? group.hashCode() : 0);
        result = 31 * result + this.getClass().getCanonicalName().hashCode();
        return result;
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
