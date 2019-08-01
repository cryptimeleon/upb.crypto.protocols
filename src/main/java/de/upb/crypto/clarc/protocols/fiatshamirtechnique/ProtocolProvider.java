package de.upb.crypto.clarc.protocols.fiatshamirtechnique;

import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.parameters.Problem;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * This interface marks a serializable way to represent a function to create instances of {@link InteractiveThreeWayAoK}
 * to be used, for example, in {@link FiatShamirSignatureScheme}.
 */
public interface ProtocolProvider extends StandaloneRepresentable {

    /**
     * @param instance instance x to generate a {@link InteractiveThreeWayAoK} for
     * @param witness  witness w for x, might be an {@link de.upb.crypto.clarc.protocols.parameters.EmptyWitness}
     * @return {@link InteractiveThreeWayAoK} instance for given {@code instance} and {@code witness}
     */
    InteractiveThreeWayAoK getProtocolInstance(Problem[] instance, Witness[] witness);
}
