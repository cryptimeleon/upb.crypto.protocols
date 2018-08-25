package de.upb.crypto.clarc.protocols.arguments;

import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Problem;
import de.upb.crypto.clarc.protocols.parameters.Witness;
import de.upb.crypto.clarc.protocols.simulator.SpecialHonestVerifierSimulator;
import de.upb.crypto.clarc.protocols.simulator.Transcript;
import de.upb.crypto.craco.interfaces.PublicParameters;

import java.util.List;

public interface SpecialHonestVerifierZeroKnowledgeThreeWayAoK extends InteractiveThreeWayAoK {
    /**
     * In case an {@link SpecialHonestVerifierSimulator} can not actually be fulfilled it can be simulated.
     * <br>
     * A {@link SpecialHonestVerifierSimulator} takes a {@link Challenge} as input for the simulation to calculate a
     * valid {@link Transcript}
     *
     * @return {@link SpecialHonestVerifierSimulator} for an execution of the
     * {@link SpecialHonestVerifierZeroKnowledgeThreeWayAoK} which outputs a valid {@link Transcript} when
     * given a {@link Challenge} as input
     */
    @Override
    SpecialHonestVerifierSimulator getSimulator();

    Problem[] getProblems();

    Witness[] getWitnesses();

    /**
     * set the witnesses with the given list.
     * If any witness is set, the value is overwritten.
     * The matching of the witnesses is done via the same name.
     *
     * @param witnesses the witnesses that should be used fot the protocol
     * @return The protocol with set witnesses
     */
    SpecialHonestVerifierZeroKnowledgeThreeWayAoK setWitnesses(List<Witness> witnesses);

    PublicParameters getPublicParameters();
}
