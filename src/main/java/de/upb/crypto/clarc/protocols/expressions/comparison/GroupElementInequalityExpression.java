package de.upb.crypto.clarc.protocols.expressions.comparison;

import de.upb.crypto.clarc.protocols.expressions.GroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.ZnElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.arith.ArithExpression;
import de.upb.crypto.clarc.protocols.expressions.arith.ArithGroupElementExpression;
import de.upb.crypto.craco.interfaces.policy.PolicyFact;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.util.Collection;

public class GroupElementInequalityExpression implements GroupElementComparisonExpression {

    private ArithGroupElementExpression lhs;
    private ArithGroupElementExpression rhs;

    public GroupElementInequalityExpression(ArithGroupElementExpression lhs, ArithGroupElementExpression rhs) {
        this.lhs = lhs;
        this.rhs = rhs;
    }

    public GroupElementInequalityExpression(Representation representation) {
        this.lhs = (ArithGroupElementExpression) representation.obj().get("lhs").repr().recreateRepresentable();
        this.rhs = (ArithGroupElementExpression) representation.obj().get("rhs").repr().recreateRepresentable();
    }

    @Override
    public GroupElement evaluateLHS(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts) {
        return lhs.calculateResult(groupFacts, znFacts);
    }

    @Override
    public GroupElement evaluateRHS(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts) {
        return rhs.calculateResult(groupFacts, znFacts);
    }

    @Override
    public EquationPrimitives getComparator() {
        return EquationPrimitives.NOT_EQUAL;
    }

    @Override
    public ArithExpression getLHS() {
        return lhs;
    }

    @Override
    public ArithExpression getRHS() {
        return rhs;
    }


    @Override
    public void setLhs(ArithGroupElementExpression lhs) {
        this.lhs = lhs;
    }

    @Override
    public void setRhs(ArithGroupElementExpression rhs) {
        this.rhs = rhs;
    }

    @Override
    public boolean isFulfilled(Collection<? extends PolicyFact> facts) {
        GroupElementPolicyFacts groupFacts = getGroupFacts(facts);
        ZnElementPolicyFacts znFacts = getZnFacts(facts);

        return !lhs.resultAsEfficientExpression(groupFacts, znFacts)
                .op(rhs.resultAsEfficientExpression(groupFacts, znFacts).inv())
                .evaluate().isNeutralElement();

    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("lhs", new RepresentableRepresentation(lhs));
        repr.put("rhs", new RepresentableRepresentation(rhs));
        return repr;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        GroupElementInequalityExpression that = (GroupElementInequalityExpression) o;

        if (lhs != null ? !lhs.equals(that.lhs) : that.lhs != null) return false;
        return rhs != null ? rhs.equals(that.rhs) : that.rhs == null;
    }

    @Override
    public int hashCode() {
        int result = lhs != null ? lhs.hashCode() : 0;
        result = 31 * result + (rhs != null ? rhs.hashCode() : 0);
        result = 31 * result + this.getClass().getCanonicalName().hashCode();
        return result;
    }

}
