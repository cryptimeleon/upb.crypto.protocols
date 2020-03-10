package de.upb.crypto.clarc.protocols.schnorr.stmts.api;

import de.upb.crypto.clarc.protocols.schnorr.SchnorrImage;
import de.upb.crypto.math.expressions.bool.BoolEmptyExpr;
import de.upb.crypto.math.expressions.bool.BooleanExpression;
import de.upb.crypto.math.expressions.group.GroupElementExpression;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.FutureGroupElement;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.math.BigInteger;
import java.util.Arrays;

public class GroupElementImage implements SchnorrImage {
    protected GroupElementExpression[] groupElems;
    protected FutureGroupElement[] results = null;

    public GroupElementImage(GroupElementExpression... groupElems) {
        this.groupElems = groupElems;
    }

    public GroupElementImage(Representation repr, Group[] groups) {
        groupElems = new GroupElementExpression[groups.length];
        for (int i=0;i<groupElems.length;i++)
            groupElems[i] = groups[i].getElement(repr.list().get(i)).expr();
    }

    public GroupElementImage(Representation repr, Group group) {
        groupElems = new GroupElementExpression[repr.list().size()];
        for (int i=0;i<groupElems.length;i++)
            groupElems[i] = group.getElement(repr.list().get(i)).expr();
    }

    @Override
    public SchnorrImage op(SchnorrImage operand) {
        if (!(operand instanceof GroupElementImage) || ((GroupElementImage) operand).groupElems.length != this.groupElems.length)
            throw new IllegalArgumentException("Images are incompatible");

        GroupElementExpression[] result = new GroupElementExpression[groupElems.length];
        for (int i=0;i<groupElems.length;i++)
            result[i] = groupElems[i].op(((GroupElementImage) operand).groupElems[i]);
        return new GroupElementImage(result);
    }

    @Override
    public SchnorrImage pow(BigInteger exponent) {
        GroupElementExpression[] result = new GroupElementExpression[groupElems.length];
        for (int i=0;i<groupElems.length;i++)
            result[i] = groupElems[i].pow(exponent);
        return new GroupElementImage(result);
    }

    @Override
    public BooleanExpression isEqualTo(SchnorrImage image) {
        if (!(image instanceof GroupElementImage) || ((GroupElementImage) image).groupElems.length != this.groupElems.length)
            throw new IllegalArgumentException("Images are incompatible");

        BooleanExpression result = new BoolEmptyExpr();
        for (int i=0;i<groupElems.length;i++)
            result = result.and(groupElems[i].isEqualTo(((GroupElementImage) image).groupElems[i]));
        return result;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        compute();
        for (FutureGroupElement elem : results)
            accumulator.escapeAndSeparate(elem.get());

        return accumulator;
    }

    @Override
    public Representation getRepresentation() {
        compute();
        ListRepresentation repr = new ListRepresentation();
        for (FutureGroupElement elem : results)
            repr.add(elem.get().getRepresentation());

        return repr;
    }

    protected void compute() {
        if (results != null)
            return;
        results = new FutureGroupElement[groupElems.length];

        for (int i=0;i< groupElems.length;i++)
            results[i] = groupElems[i].evaluateAsync();
    }

    @Override
    public String toString() {
        compute();
        return "GroupElementImage{" +
                ", results=" + Arrays.toString(Arrays.stream(results).map(FutureGroupElement::get).toArray()) +
                '}';
    }
}
