package de.upb.crypto.clarc.protocols.parameters;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.List;
import java.util.Objects;

/**
 * An empty witness, having only a name.
 * Can be used as placeholder for verifier
 */
public class EmptyWitness implements Witness {

    @Represented
    private String name;

    /**
     * This constructor must be used, if the witness name is eventually used.
     * This is especially the case, if  {@link SigmaProtocol#setWitnesses(List)} is called on the sigma
     * protocol that uses this witness.
     *
     * @param name the unique name of the witness. The name must be at least unique in the scope of the protocol. If
     *             the protocol is used in a subroutine of another protocol, uniqueness needs to be guaranteed for
     *             the "whole protocol context".
     */
    public EmptyWitness(String name) {
        this.name = name;
    }

    /**
     * The name of the witness is set to the empty string in this constructor. Thereby, the witness cannot be set
     * later on.
     * <b>Use this Constructor only if you are 100% sure that the witness will never be set afterwards</b> (normaly
     * only on verifier side or in a simulator
     */
    public EmptyWitness() {
        name = "";
    }

    public EmptyWitness(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    @Override
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EmptyWitness that = (EmptyWitness) o;
        return Objects.equals(getName(), that.getName());
    }

    @Override
    public int hashCode() {

        return Objects.hash(getName());
    }
}
