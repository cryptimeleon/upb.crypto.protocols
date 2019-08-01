package de.upb.crypto.clarc.protocols.arguments;

import de.upb.crypto.clarc.protocols.TwoPartyProtocolInstance;

public interface InteractiveArgumentInstance extends TwoPartyProtocolInstance {
    /**
     * Call after protocol has terminated.
     * Returns true (for the Verifier) if the protocol is accepting (i.e. the prover was able to convince the verifier)
     */
    boolean isAccepting();
}
