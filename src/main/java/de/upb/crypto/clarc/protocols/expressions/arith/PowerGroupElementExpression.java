package de.upb.crypto.clarc.protocols.expressions.arith;

import de.upb.crypto.clarc.protocols.expressions.GroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.ZnElementPolicyFacts;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.interfaces.structures.GroupElementMixedExpression;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;

public class PowerGroupElementExpression extends BinaryExpression implements ArithGroupElementExpression,
        PowerExpression {


    private ArithGroupElementExpression base;
    private ArithZnElementExpression exponent;

    public PowerGroupElementExpression(ArithGroupElementExpression base, ArithZnElementExpression exponent) {
        this.base = base;
        this.exponent = exponent;
    }

    public PowerGroupElementExpression(Representation representation) {
        this.base = (ArithGroupElementExpression) representation.obj().get("base").repr().recreateRepresentable();
        this.exponent = (ArithZnElementExpression) representation.obj().get("exponent").repr().recreateRepresentable();
    }

    @Override
    public GroupElementMixedExpression resultAsEfficientExpression(GroupElementPolicyFacts groupFacts,
                                                                   ZnElementPolicyFacts znFacts) {
        return base.resultAsEfficientExpression(groupFacts, znFacts).pow(exponent.calculateResult(groupFacts, znFacts));
    }

    @Override
    public GroupElement calculateResult(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts) {
        return base.calculateResult(groupFacts, znFacts).pow(exponent.calculateResult(groupFacts, znFacts));
    }

    @Override
    public ArithGroupElementExpression getLHS() {
        return base;
    }

    @Override
    public ArithZnElementExpression getRHS() {
        return exponent;
    }

    public void setBase(ArithGroupElementExpression base) {
        this.base = base;
    }

    public void setExponent(ArithZnElementExpression exponent) {
        this.exponent = exponent;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("base", new RepresentableRepresentation(base));
        repr.put("exponent", new RepresentableRepresentation(exponent));
        return repr;
    }

    @Override
    public String getOp() {
        return op;
    }

}
