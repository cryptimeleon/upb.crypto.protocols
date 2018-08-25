package de.upb.crypto.clarc.protocols.expressions.arith;

import de.upb.crypto.clarc.protocols.expressions.GroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.ZnElementPolicyFacts;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.interfaces.structures.GroupElementMixedExpression;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.Set;

public class PairingGroupElementExpression implements ArithGroupElementExpression, PairingUsage {

    @UniqueByteRepresented
    private final String op = "pairing";
    private final BilinearMap map;

    @UniqueByteRepresented
    private final ArithGroupElementExpression firstArg;

    @UniqueByteRepresented
    private final ArithGroupElementExpression secondArg;

    @UniqueByteRepresented
    private final ArithZnElementExpression exponents;

    public PairingGroupElementExpression(BilinearMap map, ArithGroupElementExpression firstArg,
                                         ArithGroupElementExpression secondArg, BigInteger exponents) {
        this.map = map;
        this.firstArg = firstArg;
        this.secondArg = secondArg;
        this.exponents = new NumberZnElementLiteral(new Zp(map.getG2().size()).createZnElement(exponents));
    }

    public PairingGroupElementExpression(BilinearMap map, ArithGroupElementExpression firstArg,
                                         ArithGroupElementExpression secondArg, ArithZnElementExpression exponents) {
        this.map = map;
        this.firstArg = firstArg;
        this.secondArg = secondArg;
        this.exponents = exponents;
    }

    public PairingGroupElementExpression(Representation representation) {
        this.map = (BilinearMap) representation.obj().get("map").repr().recreateRepresentable();
        this.firstArg = (ArithGroupElementExpression) representation.obj().get("firstArg").repr()
                .recreateRepresentable();
        this.secondArg = (ArithGroupElementExpression) representation.obj().get("secondArg").repr()
                .recreateRepresentable();
        this.exponents = (ArithZnElementExpression) representation.obj().get("exponent").repr().recreateRepresentable();
    }

    public PairingGroupElementExpression(BilinearMap map, ArithGroupElementExpression firstArg,
                                         ArithGroupElementExpression secondArg) {
        this.map = map;
        this.firstArg = firstArg;
        this.secondArg = secondArg;
        this.exponents = new NumberZnElementLiteral(new Zp(map.getG2().size()).createZnElement(BigInteger.ONE));
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("map", new RepresentableRepresentation(map));
        repr.put("firstArg", new RepresentableRepresentation(firstArg));
        repr.put("secondArg", new RepresentableRepresentation(secondArg));
        repr.put("exponent", new RepresentableRepresentation(exponents));
        return repr;
    }

    @Override
    public GroupElementMixedExpression resultAsEfficientExpression(GroupElementPolicyFacts groupFacts,
                                                                   ZnElementPolicyFacts znFacts) {
        //Information: Note that the pairing expression implements a stateless behaviour, meaning that previous
        // values for
        // the exponents are ignored.

        GroupElementMixedExpression result = new GroupElementMixedExpression(
                map.pairingProductExpression().op(firstArg.resultAsEfficientExpression(groupFacts, znFacts).getPowExpr(),
                        secondArg.resultAsEfficientExpression(groupFacts, znFacts).getPowExpr()));

        if (exponents != null) {
            result.pow(exponents.calculateResult(groupFacts, znFacts).getInteger());
        }

        return result;
    }

    @Override
    public GroupElement calculateResult(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts) {
        //Information: Note that the pairing expression implements a stateless behaviour, meaning that previous
        // values for
        // the exponents are ignored.
        BigInteger exp = BigInteger.ONE;
        if (exponents != null) {
            exp = exponents.calculateResult(groupFacts, znFacts).getInteger();
        }
        GroupElement g1 = firstArg.calculateResult(groupFacts, znFacts);
        GroupElement g2 = secondArg.calculateResult(groupFacts, znFacts);
        if (g1.getStructure().equals(map.getG1())) {
            if (g2.getStructure().equals(map.getG2())) {
                return map.apply((g1), g2, exp);

            }
            throw new IllegalArgumentException("The second argument does not evaluate to a G2 element");
        }
        throw new IllegalArgumentException("The first argument does not evaluate to a G1 Element");
    }

    @Override
    public boolean isDetermined() {
        return firstArg.isDetermined() && secondArg.isDetermined() && (exponents == null || exponents.isDetermined());
    }

    @Override
    public void getVariables(Set<Variable> result) {
        firstArg.getVariables(result);
        secondArg.getVariables(result);
        if (exponents != null)
            exponents.getVariables(result);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PairingGroupElementExpression that = (PairingGroupElementExpression) o;

        if (map != null ? !map.equals(that.map) : that.map != null) return false;
        if (firstArg != null ? !firstArg.equals(that.firstArg) : that.firstArg != null) return false;
        if (secondArg != null ? !secondArg.equals(that.secondArg) : that.secondArg != null) return false;
        return exponents != null ? exponents.equals(that.exponents) : that.exponents == null;
    }

    @Override
    public int hashCode() {
        int result = map != null ? map.hashCode() : 0;
        result = 31 * result + (firstArg != null ? firstArg.hashCode() : 0);
        result = 31 * result + (secondArg != null ? secondArg.hashCode() : 0);
        result = 31 * result + (exponents != null ? exponents.hashCode() : 0);
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
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("(");
        builder.append(op);
        builder.append("(");
        builder.append(firstArg.toString());
        builder.append(",");
        builder.append(secondArg.toString());
        builder.append(")");
        if (!(exponents.equals(new Zp(map.getG2().size()).getOneElement()))) {
            builder.append("^");
            builder.append(exponents.toString());
        }
        return builder.toString();
    }
}
