package de.upb.crypto.clarc.protocols.schnorr;

import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.util.List;

public class SchnorrAnnouncement implements Announcement {
    protected List<GroupElement> announcements;

    public SchnorrAnnouncement(List<GroupElement> announcements) {
        this.announcements = announcements;
    }

    @Override
    public Representation getRepresentation() {
        ListRepresentation repr = new ListRepresentation();
        announcements.stream().forEachOrdered(g -> repr.put(g.getRepresentation()));
        return repr;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        for (GroupElement elem : announcements)
            byteAccumulator.escapeAndAppendAndSeparate(elem);
        return byteAccumulator;
    }
}
