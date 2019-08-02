package de.upb.crypto.clarc.protocols.arguments;

import de.upb.crypto.clarc.protocols.TwoPartyProtocolInstance;
import de.upb.crypto.math.expressions.bool.BooleanExpression;

public interface InteractiveArgumentInstance extends TwoPartyProtocolInstance {
    /**
     * Call on the verifier after protocol has terminated.
     * Returns true if the protocol is accepting (i.e. the prover was able to convince the verifier)
     */
    default boolean isAccepting() {
        return getAcceptanceExpression().evaluate();
    }

    /**
     * Call on the verifier after protocol has terminated.
     * Returns an expression that evaluates to true if the protocol is accepting (i.e. the prover was able to convince the verifier).
     *
     * If you have several protocols, it may be more efficient to concatenate the expressions of each of them and evaluate the composite.
     */
    BooleanExpression getAcceptanceExpression();

    @Override
    InteractiveArgument getProtocol();
}
