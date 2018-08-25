package de.upb.crypto.clarc.protocols.expressions.comparison;

import de.upb.crypto.clarc.protocols.expressions.GroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.ZnElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.arith.ArithGroupElementExpression;
import de.upb.crypto.math.interfaces.structures.GroupElement;

/**
 * A Comparison expression comparing two
 * {@link de.upb.crypto.clarc.protocols.expressions.arith.ArithGroupElementExpression}
 */
public interface GroupElementComparisonExpression extends ArithComparisonExpression {
    /**
     * Returns the result (a Group Element) obtained by evaluating the LHS of the equation
     *
     * @param groupFacts the GroupElementsPolicyFacts needed to evaluate the LHS
     * @param znFacts    the ZnElementsPolicyFacts needed to evaluate the LHS
     * @return a group element that's the result of the evaluation
     */
    GroupElement evaluateLHS(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts);

    /**
     * Returns the result (a Group Element) obtained by evaluating the RHS of the equation
     *
     * @param groupFacts the GroupElementsPolicyFacts needed to evaluate the RHS
     * @param znFacts    the ZnElementsPolicyFacts needed to evaluate the LHS
     * @return a group element that's the result of the evaluation
     */
    GroupElement evaluateRHS(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts);


    void setLhs(ArithGroupElementExpression lhs);

    void setRhs(ArithGroupElementExpression rhs);
}
