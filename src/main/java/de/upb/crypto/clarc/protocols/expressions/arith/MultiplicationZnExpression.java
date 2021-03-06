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

public class MultiplicationZnExpression extends NAryExpression implements ArithZnElementExpression,
        MultiplicationExpression {

    private List<ArithZnElementExpression> factors;

    public MultiplicationZnExpression(List<ArithZnElementExpression> factors) {
        this.factors = factors;
    }

    public MultiplicationZnExpression(Representation representation) {
        factors = new ArrayList<>();
        representation.list().getList().forEach(r -> factors.add((ArithZnElementExpression) r.repr()
                .recreateRepresentable()));
    }

    @Override
    public boolean addElement(ArithExpression element) {
        if (element instanceof AdditionZnExpression) {
            return this.factors.add((ArithZnElementExpression) element);
        } else {
            throw new IllegalArgumentException("The given Object does not have a valid type!");
        }
    }

    @Override
    public boolean removeElement(ArithExpression element) {
        if (element instanceof ArithZnElementExpression) {
            return this.factors.remove(element);
        } else {
            throw new IllegalArgumentException("The given Object does not have a valid type!");
        }
    }

    @Override
    public List<ArithZnElementExpression> getElements() {
        return new ArrayList<>(factors);
    }

    @Override
    public void setElements(List<ArithExpression> elements) {
        if (elements.stream().allMatch(element -> element instanceof ArithZnElementExpression)) {
            this.factors = elements.stream().map(element -> (ArithZnElementExpression) element).collect(Collectors
                    .toList());
        } else {
            throw new IllegalArgumentException("The given Object does not have a valid type!");
        }
    }

    @Override
    public String getOp() {
        return op;
    }

    @Override
    public Zn.ZnElement calculateResult(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts) {
        if (!factors.isEmpty()) {
            Zn.ZnElement res = factors.get(0).calculateResult(groupFacts, znFacts).getStructure().getOneElement();
            for (ArithZnElementExpression ele : factors) {
                res = res.mul(ele.calculateResult(groupFacts, znFacts));
            }
            return res;
        } else {
            throw new IllegalArgumentException("The list of factors can not be empty.");
        }
    }

    @Override
    public Representation getRepresentation() {
        ListRepresentation repr = new ListRepresentation();
        factors.forEach(f -> repr.put(new RepresentableRepresentation(f)));
        return repr;
    }


}
