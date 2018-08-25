package de.upb.crypto.clarc.protocols.parameters;

import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.util.Arrays;

/**
 * Empty problem if there is not anythings meaningful to put in here.
 */
public class EmptyProblem implements Problem {

    public EmptyProblem() {
    }

    public EmptyProblem(Representation representation) {
    }

    @Override
    public Representation getRepresentation() {
        return new ObjectRepresentation();
    }

    @Override
    public boolean equals(Object obj) {
        return obj instanceof EmptyProblem;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(this.getClass().getName().getBytes());
    }
}
