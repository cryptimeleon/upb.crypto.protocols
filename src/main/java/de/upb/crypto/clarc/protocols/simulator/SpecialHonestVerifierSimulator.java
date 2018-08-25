package de.upb.crypto.clarc.protocols.simulator;

import de.upb.crypto.clarc.protocols.arguments.SpecialHonestVerifierZeroKnowledgeThreeWayAoK;
import de.upb.crypto.clarc.protocols.parameters.Challenge;

/**
 * A verifier for a Sigma protocol with special honest verifier property. The simulator is bounded to a special
 * protocol and therefore take the protocol as input.
 * The simulator works in general as follows: On input of a challenge the responses are chosen uniformly at random
 * and fixes thereby the randomness used in the protocol.
 * Afterwards, the announcement is calculated in the way, that it fulfills the verification equation in the verify step.
 */
public abstract class SpecialHonestVerifierSimulator extends Simulator<SpecialHonestVerifierZeroKnowledgeThreeWayAoK> {

    /**
     * Constructor for the Simulator
     *
     * @param protocolInstance that will be simulated by the protocol.
     */
    public SpecialHonestVerifierSimulator(SpecialHonestVerifierZeroKnowledgeThreeWayAoK protocolInstance) {
        super(protocolInstance);
    }

    /**
     * This method is deprecated, since it is not applicable for the type of simulator. A challenge is needed. See
     * {@link SpecialHonestVerifierSimulator#simulate(Challenge)}
     *
     * @return an {@link IllegalStateException}, since this method is not applicable here
     */
    @Override
    @Deprecated
    public Transcript simulate() {
        throw new IllegalStateException("This type of  simulate-method is not applicable for a " +
                "SpecialHonestVerifierSimulator");
    }

    /**
     * Simulation for the protocol based on the challenge. The simulator works in general as follows: On input of a
     * challenge the responses are chosen uniformly at random and fixes thereby the randomness used in the protocol.
     * Afterwards, the announcement is calculated in the way, that it fulfills the verification equation in the
     * verify step.
     *
     * @param challege used for the simulation.
     * @return an accepting transcript with the given challenge.
     */
    public abstract Transcript simulate(Challenge challege);

}