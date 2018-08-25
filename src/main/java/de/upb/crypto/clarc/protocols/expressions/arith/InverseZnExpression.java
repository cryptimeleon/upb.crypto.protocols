package de.upb.crypto.clarc.protocols.expressions.arith;

import de.upb.crypto.clarc.protocols.expressions.GroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.ZnElementPolicyFacts;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zn;

public class InverseZnExpression extends UnaryExpression implements ArithZnElementExpression, InverseExpression {

    private ArithZnElementExpression element;

    public InverseZnExpression(ArithZnElementExpression element) {
        this.element = element;
    }

    public InverseZnExpression(Representation representation) {
        element = (ArithZnElementExpression) representation.repr().recreateRepresentable();
    }

    @Override
    public String getOp() {
        return op;
    }

    @Override
    public Zn.ZnElement calculateResult(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts) {
        return element.calculateResult(groupFacts, znFacts).inv();
    }

    public ArithZnElementExpression getElement() {
        return element;
    }

    public void setElement(ArithZnElementExpression element) {
        this.element = element;
    }

    @Override
    public Representation getRepresentation() {
        return new RepresentableRepresentation(element);
    }

}
