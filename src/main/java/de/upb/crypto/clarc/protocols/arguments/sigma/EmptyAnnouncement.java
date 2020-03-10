package de.upb.crypto.clarc.protocols.arguments.sigma;

import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;

public class EmptyAnnouncement implements Announcement {
    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return accumulator;
    }

    @Override
    public Representation getRepresentation() {
        return null;
    }
}
