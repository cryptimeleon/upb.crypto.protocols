package de.upb.crypto.clarc.protocols.expressions.arith;

import de.upb.crypto.clarc.protocols.expressions.GroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.ZnElementPolicyFacts;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.interfaces.structures.GroupElementMixedExpression;

public interface ArithGroupElementExpression extends ArithExpression {

    @Override
    GroupElement calculateResult(
            GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts);

    /**
     * Returns the result in the form of a GroupElementExpression (cf. math library),
     * which can be efficiently evaluated.
     * Semantically equivalent to calculateResult(), but returns a GroupElementExpression instead of the GroupElement.
     *
     * @param groupFacts
     * @param znFacts
     * @return
     */
    GroupElementMixedExpression resultAsEfficientExpression(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts);
}
