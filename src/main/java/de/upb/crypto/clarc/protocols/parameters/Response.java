package de.upb.crypto.clarc.protocols.parameters;

import de.upb.crypto.math.serialization.Representable;

/**
 * A response is the third message of a three way protocol. It is computed by the prover for the received challenge
 * from the verifier. Some protocols may use more than one response.
 */
public interface Response extends Representable {
    String RECOVERY_METHOD = "recreateResponse";
}
