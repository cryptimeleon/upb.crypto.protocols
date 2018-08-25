package de.upb.crypto.clarc.protocols.expressions.arith;


import de.upb.crypto.clarc.protocols.expressions.GroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.ZnElementPolicyFacts;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.interfaces.structures.GroupElementMixedExpression;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class ProductGroupElementExpression extends NAryExpression implements ProductExpression,
        ArithGroupElementExpression {

    private List<ArithGroupElementExpression> factors;

    public ProductGroupElementExpression() {
        this.factors = new ArrayList<>();
    }

    public ProductGroupElementExpression(List<ArithGroupElementExpression> factors) {
        this.factors = new ArrayList<>(factors);
    }

    public ProductGroupElementExpression(ArithGroupElementExpression... factors) {
        this(Arrays.asList(factors));
    }

    public ProductGroupElementExpression(Representation representation) {
        factors = new ArrayList<>();
        representation.list().getList().forEach(r -> factors.add((ArithGroupElementExpression) r.repr()
                .recreateRepresentable()));
    }

    @Override
    public GroupElementMixedExpression resultAsEfficientExpression(GroupElementPolicyFacts groupFacts,
                                                                   ZnElementPolicyFacts znFacts) {
        if (!factors.isEmpty()) {
            GroupElementMixedExpression res = factors.get(0).resultAsEfficientExpression(groupFacts, znFacts);
            for (int i = 1; i < factors.size(); i++) {
                res.op(factors.get(i).resultAsEfficientExpression(groupFacts, znFacts));
            }
            return res;
        } else {
            throw new IllegalArgumentException("The list of factors must contain at least on element!");
        }
    }

    @Override
    public GroupElement calculateResult(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts) {
        if (!factors.isEmpty()) {
            GroupElement res;
            res = factors.get(0).calculateResult(groupFacts, znFacts).getStructure().getNeutralElement();
            for (ArithGroupElementExpression e : factors) {
                res = res.op(e.calculateResult(groupFacts, znFacts));
            }
            return res;
        } else {

            throw new IllegalArgumentException("The list of factors must contain at least on element!");
        }
    }

    @Override
    public String getOp() {
        return op;
    }

    @Override
    public boolean addElement(ArithExpression element) {
        if (element instanceof ArithGroupElementExpression) {
            return this.factors.add((ArithGroupElementExpression) element);
        } else {
            throw new IllegalArgumentException("The given Object does not have a valid type!");
        }
    }

    @Override
    public boolean removeElement(ArithExpression element) {
        if (element instanceof ArithGroupElementExpression) {
            return this.factors.remove(element);
        } else {
            throw new IllegalArgumentException("The given Object does not have a valid type!");
        }
    }

    @Override
    public List<ArithGroupElementExpression> getElements() {
        return new ArrayList<>(factors);
    }

    @Override
    public void setElements(List<ArithExpression> elements) {
        if (elements == null || elements.isEmpty()) {
            throw new IllegalArgumentException("The list of factors can not be null or empty");
        }
        if (elements.stream().allMatch(element -> element instanceof ArithGroupElementExpression)) {
            this.factors = elements.stream().map(element -> (ArithGroupElementExpression) element).collect(Collectors
                    .toList());
        } else {
            throw new IllegalArgumentException("The given Object does not have a valid type!");
        }
    }

    @Override
    public Representation getRepresentation() {
        ListRepresentation repr = new ListRepresentation();
        factors.forEach(f -> repr.put(new RepresentableRepresentation(f)));
        return repr;
    }
}
