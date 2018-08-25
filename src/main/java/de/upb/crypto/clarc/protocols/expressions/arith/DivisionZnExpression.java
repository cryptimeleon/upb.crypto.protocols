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

public class DivisionZnExpression extends NAryExpression implements ArithZnElementExpression, DivisionExpression {

    private List<ArithZnElementExpression> divisors;

    public DivisionZnExpression(List<ArithZnElementExpression> factors) {
        this.divisors = factors;
    }

    public DivisionZnExpression(Representation representation) {
        divisors = new ArrayList<>();
        representation.list().getList().forEach(r -> divisors.add(
                (ArithZnElementExpression) r.repr().recreateRepresentable()));
    }

    @Override
    public String getOp() {
        return op;
    }

    @Override
    public boolean addElement(ArithExpression element) {
        if (element instanceof AdditionZnExpression) {
            return this.divisors.add((ArithZnElementExpression) element);
        } else {
            throw new IllegalArgumentException("The given Object does not have a valid type!");
        }
    }

    @Override
    public boolean removeElement(ArithExpression element) {
        if (element instanceof ArithZnElementExpression) {
            return this.divisors.remove(element);
        } else {
            throw new IllegalArgumentException("The given Object does not have a valid type!");
        }
    }

    @Override
    public List<ArithZnElementExpression> getElements() {
        return new ArrayList<>(divisors);
    }

    @Override
    public void setElements(List<ArithExpression> elements) {
        if (elements.stream().allMatch(element -> element instanceof ArithZnElementExpression)) {
            this.divisors = elements.stream().map(element -> (ArithZnElementExpression) element).collect(Collectors
                    .toList());
        } else {
            throw new IllegalArgumentException("The given Object does not have a valid type!");
        }
    }

    @Override
    public Zn.ZnElement calculateResult(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts) {
        if (!divisors.isEmpty()) {
            Zn.ZnElement res = divisors.get(0).calculateResult(groupFacts, znFacts);
            for (int i = 1; i < divisors.size(); i++) {
                res = (Zn.ZnElement) res.div(divisors.get(i).calculateResult(groupFacts, znFacts));
            }
            return res;
        } else {
            throw new IllegalArgumentException("The list of divisors can not be empty. (If only one element is given," +
                    " the element will be returned.)");
        }
    }

    @Override
    public Representation getRepresentation() {
        ListRepresentation repr = new ListRepresentation();
        divisors.forEach(d -> repr.put(new RepresentableRepresentation(d)));
        return repr;
    }
}
