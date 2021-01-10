package de.upb.crypto.clarc.protocols.arguments;

import de.upb.crypto.clarc.protocols.TwoPartyProtocolInstance;
import de.upb.crypto.math.expressions.bool.BooleanExpression;

public interface InteractiveArgumentInstance extends TwoPartyProtocolInstance {
    /**
     * Called on the verifier after protocol has terminated.
     * Returns true if the protocol is accepting (i.e. the prover was able to convince the verifier)
     */
    boolean isAccepting();

    @Override
    InteractiveArgument getProtocol();
}
