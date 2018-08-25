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

public class SubtractionZnExpression extends NAryExpression implements ArithZnElementExpression, SubtractionExpression {

    private List<ArithZnElementExpression> subtrahends;

    public SubtractionZnExpression(List<ArithZnElementExpression> factors) {
        this.subtrahends = factors;
    }

    public SubtractionZnExpression(Representation representation) {
        subtrahends = new ArrayList<>();
        representation.list().getList().forEach(r -> subtrahends.add(
                (ArithZnElementExpression) r.repr().recreateRepresentable()));
    }

    @Override
    public String getOp() {
        return op;
    }

    @Override
    public boolean addElement(ArithExpression element) {
        if (element instanceof AdditionZnExpression) {
            return this.subtrahends.add((ArithZnElementExpression) element);
        } else {
            throw new IllegalArgumentException("The given Object does not have a valid type!");
        }
    }

    @Override
    public boolean removeElement(ArithExpression element) {
        if (element instanceof ArithZnElementExpression) {
            return this.subtrahends.remove(element);
        } else {
            throw new IllegalArgumentException("The given Object does not have a valid type!");
        }
    }

    @Override
    public List<ArithZnElementExpression> getElements() {
        return new ArrayList<>(subtrahends);
    }

    @Override
    public void setElements(List<ArithExpression> elements) {
        if (elements.stream().allMatch(element -> element instanceof ArithZnElementExpression)) {
            this.subtrahends = elements.stream().map(element -> (ArithZnElementExpression) element).collect
                    (Collectors.toList());
        } else {
            throw new IllegalArgumentException("The given Object does not have a valid type!");
        }
    }

    @Override
    public Representation getRepresentation() {
        ListRepresentation repr = new ListRepresentation();
        subtrahends.forEach(s -> repr.put(new RepresentableRepresentation(s)));
        return repr;

    }

    @Override
    public Zn.ZnElement calculateResult(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts) {
        if (!subtrahends.isEmpty()) {
            Zn.ZnElement res = subtrahends.get(0).calculateResult(groupFacts, znFacts);
            for (int i = 1; i < subtrahends.size(); i++) {
                res = (Zn.ZnElement) res.sub(subtrahends.get(i).calculateResult(groupFacts, znFacts));
            }
            return res;
        } else {
            throw new IllegalArgumentException("The list of subtrahends can not be null. If only one subtrahend is " +
                    "given, nothing will happen.");
        }
    }
}
