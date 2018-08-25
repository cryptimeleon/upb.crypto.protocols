package de.upb.crypto.clarc.protocols.expressions.comparison;

import de.upb.crypto.clarc.protocols.expressions.GroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.ZnElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.arith.ArithExpression;
import de.upb.crypto.clarc.protocols.expressions.arith.ArithZnElementExpression;
import de.upb.crypto.craco.interfaces.policy.PolicyFact;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zn;

import java.util.Collection;

public class ZnElementInequalityExpression implements ZnElementComparisonExpression {

    private ArithZnElementExpression lhs;
    private ArithZnElementExpression rhs;

    public ZnElementInequalityExpression(ArithZnElementExpression lhs, ArithZnElementExpression rhs) {
        this.lhs = lhs;
        this.rhs = rhs;
    }

    public ZnElementInequalityExpression(Representation representation) {
        this.lhs = (ArithZnElementExpression) representation.obj().get("lhs").repr().recreateRepresentable();
        this.rhs = (ArithZnElementExpression) representation.obj().get("rhs").repr().recreateRepresentable();
    }

    @Override
    public Zn.ZnElement evaluateLHS(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts) {
        return lhs.calculateResult(groupFacts, znFacts);
    }

    @Override
    public Zn.ZnElement evaluateRHS(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts) {
        return rhs.calculateResult(groupFacts, znFacts);
    }

    public void setLhs(ArithZnElementExpression lhs) {
        this.lhs = lhs;
    }

    public void setRhs(ArithZnElementExpression rhs) {
        this.rhs = rhs;
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
    public boolean isFulfilled(Collection<? extends PolicyFact> facts) {
        GroupElementPolicyFacts groupFacts = getGroupFacts(facts);
        ZnElementPolicyFacts znFacts = getZnFacts(facts);

        Zn.ZnElement lhsRes = lhs.calculateResult(groupFacts, znFacts);
        Zn.ZnElement rhsRes = rhs.calculateResult(groupFacts, znFacts);
        return !lhsRes.equals(rhsRes);

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

        ZnElementInequalityExpression that = (ZnElementInequalityExpression) o;

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
