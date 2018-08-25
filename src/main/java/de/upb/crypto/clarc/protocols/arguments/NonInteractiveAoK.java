package de.upb.crypto.clarc.protocols.arguments;

import de.upb.crypto.clarc.protocols.fiatshamirtechnique.Proof;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;

public interface NonInteractiveAoK extends NonInteractiveArgument {

    /**
     * This method generates the non-interactive proof of this non-interactive argument of knowledge.
     *
     * @param auxData possible additional data that influences the proof generation. Note that this parameter is
     *                optional.
     * @return a non-interactive proof
     */
    Proof prove(UniqueByteRepresentable... auxData);

    /**
     * This method verifies the given non-interactive {@code proof}
     *
     * @param proof the non-interactive proof to be verified
     * @return true iff {@code proof} is valid for this non-interactive argument of knowledge
     */
    boolean verify(Proof proof);
}
