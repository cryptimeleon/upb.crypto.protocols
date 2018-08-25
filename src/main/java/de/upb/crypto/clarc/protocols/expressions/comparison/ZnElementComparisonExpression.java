package de.upb.crypto.clarc.protocols.expressions.comparison;

import de.upb.crypto.clarc.protocols.expressions.GroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.ZnElementPolicyFacts;
import de.upb.crypto.math.structures.zn.Zn;

/**
 * A Comparison expression comparing two
 * {@link de.upb.crypto.clarc.protocols.expressions.arith.ArithZnElementExpression}
 */
public interface ZnElementComparisonExpression extends ArithComparisonExpression {
    /**
     * Returns the result (a ZN Element) obtained by evaluating the LHS of the equation
     *
     * @param groupFacts the GroupElementsPolicyFacts needed to evaluate the LHS
     * @param znFacts    the ZnElementsPolicyFacts needed to evaluate the LHS
     * @return a zn element that's the result of the evaluation
     */
    Zn.ZnElement evaluateLHS(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts);

    /**
     * Returns the result (a ZN Element) obtained by evaluating the RHS of the equation
     *
     * @param groupFacts the GroupElementsPolicyFacts needed to evaluate the RHS
     * @param znFacts    the ZnElementsPolicyFacts needed to evaluate the RHS
     * @return a zn element that's the result of the evaluation
     */
    Zn.ZnElement evaluateRHS(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts);
}
