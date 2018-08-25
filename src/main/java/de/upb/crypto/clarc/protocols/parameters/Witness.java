package de.upb.crypto.clarc.protocols.parameters;

import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * A witness is a solution to the stated problem. It depends on the given problem.
 * The witnesses are only known to the prover and should not be computable by the interaction in the protocol.
 */
public interface Witness extends StandaloneRepresentable {
    /**
     * @return name of witnesses, unique in every protocol
     */
    String getName();
}