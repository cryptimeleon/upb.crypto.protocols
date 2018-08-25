package de.upb.crypto.clarc.protocols.arguments;


import de.upb.crypto.clarc.protocols.parameters.EmptyProblem;
import de.upb.crypto.clarc.protocols.parameters.EmptyWitness;
import de.upb.crypto.clarc.protocols.parameters.Problem;
import de.upb.crypto.clarc.protocols.parameters.Witness;
import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public abstract class SigmaProtocol implements SpecialHonestVerifierZeroKnowledgeThreeWayAoK {

    @RepresentedArray(elementRestorer = @Represented)
    protected Problem[] problems;

    protected Witness[] witnesses;
    @Represented
    protected PublicParameters publicParameters;

    /**
     * Creates a new {@link SigmaProtocol} instance with given problem description, witnesses and publicly known
     * parameters.
     * <p>
     * The witnesses may be left blank and set later via {@link SigmaProtocol#setWitnesses}.
     *
     * @param problems         problem description for the protocol instance
     * @param witnesses        witnesses to be used to prove fulfillment of the given problem
     * @param publicParameters publicly known parameters for all participants
     */
    public SigmaProtocol(Problem[] problems, Witness[] witnesses, PublicParameters publicParameters) {
        this.problems = problems;
        this.witnesses = witnesses;
        this.publicParameters = publicParameters;
    }

    /**
     * Creates a new {@link SigmaProtocol} instance with an "empty" problem for protocol implementations
     * which do not need an explicit problem definition.
     *
     * @param witnesses        witnesses to be used to prove fulfillment of the given problem
     * @param publicParameters publicly known parameters for all participants
     */
    protected SigmaProtocol(Witness[] witnesses, PublicParameters publicParameters) {
        this(new Problem[]{new EmptyProblem()}, witnesses, publicParameters);
    }


    /**
     * Creates a new {@link SigmaProtocol} instance with ith given problem description and an {@link EmptyWitness}
     * with the given unique name, in case the protocol instance to be created does not have any witnesses.
     *
     * @param uniqueName       witnesses to be used to prove fulfillment of the given problem
     * @param problems         problem description for the protocol instance
     * @param publicParameters publicly known parameters for all participants
     */
    protected SigmaProtocol(String uniqueName, Problem[] problems, PublicParameters publicParameters) {
        this(problems, new Witness[]{new EmptyWitness(uniqueName)}, publicParameters);
    }

    /**
     * Creates a new {@link SigmaProtocol} instance with an "empty" problem for protocol implementations
     * which do not need an explicit problem definition. Additionally an {@link EmptyWitness} with the given unique
     * name is set, in case the protocol instance to be created does not have any witnesses.
     *
     * @param uniqueName       witnesses to be used to prove fulfillment of the given problem
     * @param publicParameters publicly known parameters for all participants
     */
    protected SigmaProtocol(String uniqueName, PublicParameters publicParameters) {
        this(uniqueName, new Problem[]{new EmptyProblem()}, publicParameters);
    }

    protected SigmaProtocol() {
    }

    @Override
    public abstract SigmaProtocol setWitnesses(List<Witness> witnesses);

    @Override
    public Problem[] getProblems() {
        return problems;
    }

    @Override
    public Witness[] getWitnesses() {
        return witnesses;
    }

    @Override
    public PublicParameters getPublicParameters() {
        return publicParameters;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SigmaProtocol protocol = (SigmaProtocol) o;
        return Arrays.equals(problems, protocol.problems) &&
                //Arrays.equals(witnesses, protocol.witnesses) &&
                Objects.equals(publicParameters, protocol.publicParameters);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(publicParameters);
        result = 31 * result + Arrays.hashCode(problems);
        //result = 31 * result + Arrays.hashCode(witnesses);
        return result;
    }

    public void setPublicParameters(PublicParameters pp) {
        this.publicParameters = pp;
    }

    public void setProblems(Problem[] problems) {
        this.problems = problems;
    }
}
