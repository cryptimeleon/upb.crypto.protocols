package de.upb.crypto.clarc.protocols.expressions.arith;


import de.upb.crypto.clarc.protocols.expressions.GroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.ZnElementPolicyFacts;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.interfaces.structures.GroupElementMixedExpression;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;

public class InverseGroupElementExpression extends UnaryExpression implements ArithGroupElementExpression,
        InverseExpression {

    private ArithGroupElementExpression element;

    public InverseGroupElementExpression(Representation representation) {
        element = (ArithGroupElementExpression) representation.repr().recreateRepresentable();
    }

    public InverseGroupElementExpression(ArithGroupElementExpression element) {
        this.element = element;
    }

    @Override
    public String getOp() {
        return op;
    }

    @Override
    public GroupElementMixedExpression resultAsEfficientExpression(GroupElementPolicyFacts groupFacts,
                                                                   ZnElementPolicyFacts znFacts) {
        return element.resultAsEfficientExpression(groupFacts, znFacts).inv();
    }

    @Override
    public GroupElement calculateResult(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts) {
        return element.calculateResult(groupFacts, znFacts).inv();
    }

    public ArithGroupElementExpression getElement() {
        return element;
    }

    public void setElement(ArithGroupElementExpression element) {
        this.element = element;

    }

    @Override
    public Representation getRepresentation() {
        return new RepresentableRepresentation(element);
    }

}
