package de.upb.crypto.clarc.protocols.expressions.arith;

import de.upb.crypto.clarc.protocols.expressions.GroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.ZnElementPolicyFacts;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zn;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class AdditionZnExpression extends NAryExpression implements ArithZnElementExpression, AdditionExpression {

    private List<ArithZnElementExpression> summands;

    public AdditionZnExpression(List<ArithZnElementExpression> factors) {
        this.summands = factors;
    }

    public AdditionZnExpression(Representation representation) {
        summands = new ArrayList<>();
        representation.list().getList().forEach(r -> summands.add(
                (ArithZnElementExpression) r.repr().recreateRepresentable()));
    }

    @Override
    public String getOp() {
        return op;
    }

    @Override
    public boolean addElement(ArithExpression element) {
        if (element instanceof AdditionZnExpression) {
            return this.summands.add((ArithZnElementExpression) element);
        } else {
            throw new IllegalArgumentException("The given Object does not have a valid type!");
        }
    }

    @Override
    public boolean removeElement(ArithExpression element) {
        if (element instanceof ArithZnElementExpression) {
            return this.summands.remove(element);
        } else {
            throw new IllegalArgumentException("The given Object does not have a valid type!");
        }
    }

    @Override
    public List<ArithZnElementExpression> getElements() {
        return new ArrayList<>(summands);
    }

    @Override
    public void setElements(List<ArithExpression> elements) {
        if (elements.stream().allMatch(element -> element instanceof ArithZnElementExpression)) {
            this.summands = elements.stream().map(element -> (ArithZnElementExpression) element).collect(Collectors
                    .toList());
        } else {
            throw new IllegalArgumentException("The given Object does not have a valid type!");
        }
    }

    @Override
    public Zn.ZnElement calculateResult(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts) {
        if (!summands.isEmpty()) {
            Zn.ZnElement res = summands.get(0).calculateResult(groupFacts, znFacts).getStructure().getZeroElement();
            for (ArithZnElementExpression ele : summands) {
                res = res.add(ele.calculateResult(groupFacts, znFacts));
            }
            return res;
        } else {
            throw new IllegalArgumentException("The list of summands can not be empty.");
        }
    }

    @Override
    public Representation getRepresentation() {
        ListRepresentation repr = new ListRepresentation();
        summands.forEach(s -> repr.put(new RepresentableRepresentation(s)));
        return repr;
    }

}

