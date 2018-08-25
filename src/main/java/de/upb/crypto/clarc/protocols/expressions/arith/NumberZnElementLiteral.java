package de.upb.crypto.clarc.protocols.expressions.arith;

import de.upb.crypto.clarc.protocols.expressions.GroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.ZnElementPolicyFacts;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zn;

/**
 * This class represents a fixed value from the ring Zn, that can not be changed!
 */
public class NumberZnElementLiteral implements NumberLiteral, ArithZnElementExpression {

    private final Zn.ZnElement value;
    private final Zn zn;

    public NumberZnElementLiteral(Zn.ZnElement value) {
        this.value = value;
        this.zn = value.getStructure();
    }

    public NumberZnElementLiteral(Representation representation) {
        zn = (Zn) representation.obj().get("zn").repr().recreateRepresentable();
        value = zn.getElement(representation.obj().get("value"));
    }

    @Override
    public Zn.ZnElement getValue() {
        return value;
    }

    @Override
    public Zn.ZnElement calculateResult(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts) {
        return value;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("value", value.getRepresentation());
        repr.put("zn", new RepresentableRepresentation(zn));
        return repr;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        NumberZnElementLiteral that = (NumberZnElementLiteral) o;

        if (getValue() != null ? !getValue().equals(that.getValue()) : that.getValue() != null) return false;
        return zn != null ? zn.equals(that.zn) : that.zn == null;
    }

    @Override
    public int hashCode() {
        int result = getValue() != null ? getValue().hashCode() : 0;
        result = 31 * result + (zn != null ? zn.hashCode() : 0);
        result = 31 * result + this.getClass().getCanonicalName().hashCode();
        return result;
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
