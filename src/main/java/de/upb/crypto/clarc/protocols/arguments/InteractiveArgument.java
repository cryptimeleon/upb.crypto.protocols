package de.upb.crypto.clarc.protocols.arguments;

import de.upb.crypto.clarc.protocols.simulator.Simulator;
import de.upb.crypto.clarc.protocols.simulator.Transcript;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

public interface InteractiveArgument extends StandaloneRepresentable {
    /**
     * In case an {@link InteractiveArgument} can not actually be fulfilled it can possibly be simulated.
     * <p>
     * The corresponding {@link Simulator} for an execution of the {@link InteractiveArgument} outputs a valid
     * {@link Transcript}. This can for example be used during proofs of partial knowledge.
     *
     * @return {@link Simulator} for an execution of the {@link InteractiveArgument} which outputs a valid
     * {@link Transcript}.
     */
    Simulator getSimulator();
}
