package de.upb.crypto.clarc.protocols.expressions.arith;

import de.upb.crypto.clarc.protocols.expressions.GroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.ZnElementPolicyFacts;
import de.upb.crypto.math.interfaces.structures.RingElement;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zn;

public class PowerZnExpression extends BinaryExpression implements ArithZnElementExpression, PowerExpression {

    private final ArithZnElementExpression base;
    private final ArithZnElementExpression exponent;

    public PowerZnExpression(ArithZnElementExpression base, ArithZnElementExpression exponent) {
        this.base = base;
        this.exponent = exponent;
    }

    public PowerZnExpression(Representation representation) {
        this.base = (ArithZnElementExpression) representation.obj().get("base").repr().recreateRepresentable();
        this.exponent = (ArithZnElementExpression) representation.obj().get("exponent").repr().recreateRepresentable();
    }

    @Override
    public Zn.ZnElement calculateResult(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts) {

        Zn.ZnElement baseRes = base.calculateResult(groupFacts, znFacts);
        RingElement res = baseRes.pow(exponent.calculateResult(groupFacts, znFacts).getInteger());
        if (res instanceof Zn.ZnElement) {
            return (Zn.ZnElement) res;
        } else
            throw new IllegalArgumentException("The result of this Power Expression must be of type " + Zn.ZnElement
                    .class + " but it was " + res.getClass());
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("base", new RepresentableRepresentation(base));
        repr.put("exponent", new RepresentableRepresentation(exponent));
        return repr;
    }


    /**
     * @return the base of the expression
     */
    @Override
    public ArithZnElementExpression getLHS() {
        return this.base;
    }


    /**
     * @return the exponent of the expression
     */
    @Override
    public ArithZnElementExpression getRHS() {
        return this.exponent;
    }

    @Override
    public String getOp() {
        return op;
    }
}
