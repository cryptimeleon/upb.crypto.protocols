package de.upb.crypto.clarc.protocols.expressions.comparison;

import de.upb.crypto.clarc.protocols.expressions.SimpleGroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.SimpleZnElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.SuperGroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.SuperZnElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.arith.Variable;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.interfaces.policy.PolicyFact;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

import java.util.*;

public interface ComparisonExpression extends Policy, StandaloneRepresentable {

    /**
     * default method to extract the groupFacts from a collection of PolicyFacts.
     * Internally, a SuperGroupElementPolicyFact is created and all SimpleGroupElementPolicyFacts are added to this fact
     *
     * @param facts a list of all facts, containing ZnElementPolicyFact and GroupElementPolicyFacts and other facts
     * @return a SuperGroupPolicyFact-element containing all simpleGroupPolicyFact
     */
    default SuperGroupElementPolicyFacts getGroupFacts(Collection<? extends PolicyFact> facts) {
        List<SimpleGroupElementPolicyFacts> listOfFacts = new ArrayList<>();
        for (PolicyFact fact : facts) {
            if (fact instanceof SimpleGroupElementPolicyFacts) {
                listOfFacts.add((SimpleGroupElementPolicyFacts) fact);
            } else if (fact instanceof SuperGroupElementPolicyFacts) {
                Map<String, GroupElement> tempFact = ((SuperGroupElementPolicyFacts) fact).getFacts();
                listOfFacts.add(new SimpleGroupElementPolicyFacts(tempFact));
            }
        }

        return new SuperGroupElementPolicyFacts(listOfFacts);
    }

    /**
     * default method to extract the groupFacts from a collection of PolicyFacts.
     * Internally, a SuperGroupElementPolicyFact is created and all SimpleGroupElementPolicyFacts
     *
     * @param facts a list of all facts, containing ZnElementPolicyFact and GroupElementPolicyFacts and other facts
     * @return a SuperGroupPolicyFact-element containing all simpleGroupPolicyFact
     */
    default SuperZnElementPolicyFacts getZnFacts(Collection<? extends PolicyFact> facts) {
        List<SimpleZnElementPolicyFacts> listOfFacts = new ArrayList<>();
        for (PolicyFact fact : facts) {
            if (fact instanceof SimpleZnElementPolicyFacts) {
                listOfFacts.add((SimpleZnElementPolicyFacts) fact);
            } else if (facts instanceof SuperZnElementPolicyFacts) {
                listOfFacts.add(new SimpleZnElementPolicyFacts(((SuperZnElementPolicyFacts) fact).getFacts()));
            }
        }

        return new SuperZnElementPolicyFacts(listOfFacts);
    }

    /**
     * Adds variables that this expression depends on to "result"
     *
     * @param result
     */
    void getVariables(Set<Variable> result);
}
