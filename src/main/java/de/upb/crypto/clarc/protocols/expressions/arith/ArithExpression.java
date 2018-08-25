package de.upb.crypto.clarc.protocols.expressions.arith;

import de.upb.crypto.clarc.protocols.expressions.GroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.ZnElementPolicyFacts;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

import java.util.Set;


public interface ArithExpression extends StandaloneRepresentable, UniqueByteRepresentable {

    Object calculateResult(GroupElementPolicyFacts groupFacts, ZnElementPolicyFacts znFacts);

    /**
     * Returns true if the value of this expression is fully determined, i.e. does not depend on variable values.
     * Equivalent to getVariables(new Set()); set.isEmpty()
     *
     * @return
     */
    boolean isDetermined();

    /**
     * Adds variables that this expression depends on to "result"
     *
     * @param result
     */
    void getVariables(Set<Variable> result);
}
