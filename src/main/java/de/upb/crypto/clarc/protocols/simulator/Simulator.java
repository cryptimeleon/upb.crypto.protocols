package de.upb.crypto.clarc.protocols.simulator;

import de.upb.crypto.clarc.protocols.arguments.InteractiveArgument;
import de.upb.crypto.clarc.protocols.arguments.sigma.SigmaProtocolTranscript;

/**
 * Abstract class of an simulator. A Simulator simulates the execution of an interactive protocol. Therefore, it may
 * interact with the verifier to get a challenge.
 *
 * @param <Argument> The Interactive Argument the simulator will work for.
 */
public abstract class Simulator<Argument extends InteractiveArgument> {


    protected final Argument protocolInstance;

    /**
     * Constructor for the simulator
     *
     * @param protocolInstance this simulator will use and simulate.
     */
    Simulator(Argument protocolInstance) {
        this.protocolInstance = protocolInstance;
    }

    /**
     * Computes a transcript of the protocol. First, the simulator will interact with the verifier to get a challenge.
     * Therefore, the simulator needs to send an announcement to the verifier. Often, the response is computed /
     * chosen in the first step. Then, the announcement is computed in such a way, that it can later be modified to
     * fulfill the verification equation in the end (for given challenge and response).
     *
     * @return an accepting transcript or the error Symbol
     */
    public abstract SigmaProtocolTranscript simulate();
}
