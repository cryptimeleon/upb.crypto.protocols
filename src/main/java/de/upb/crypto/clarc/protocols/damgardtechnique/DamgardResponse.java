package de.upb.crypto.clarc.protocols.damgardtechnique;

import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.clarc.protocols.arguments.sigma.Response;
import de.upb.crypto.craco.commitment.interfaces.OpenValue;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.*;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * The DamgardResponse is used in Damgard's Technique. It consists of the commitment of an announcement, the
 * verify-value of the announcement and the original announcement.
 */
class DamgardResponse implements Response {

    private Response innerResponse;
    private Announcement innerAnnouncement;
    private OpenValue openValue;

    /**
     * Constructor for a DamgardResponse
     *
     * @param innerResponse response of the original protocol
     * @param innerAnnouncement     uncommitted, original announcement of inner protocol
     * @param openValue             openvalue for committed announcement
     */
    public DamgardResponse(Response innerResponse, Announcement innerAnnouncement, OpenValue openValue) {
        this.innerResponse = innerResponse;
        this.innerAnnouncement = innerAnnouncement;
        this.openValue = openValue;
    }

    public Response getInnerResponse() {
        return innerResponse;
    }

    public Announcement getInnerAnnouncement() {
        return innerAnnouncement;
    }

    public OpenValue getOpenValue() {
        return openValue;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("innerResponse", innerResponse.getRepresentation());
        repr.put("innerAnnouncement", innerAnnouncement.getRepresentation());
        repr.put("openValue", openValue.getRepresentation());
        return repr; //restorer code in DamgardTechnique
    }


    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        byteAccumulator.escapeAndSeparate(innerResponse);
        byteAccumulator.escapeAndSeparate(innerAnnouncement);
        byteAccumulator.escapeAndAppend(openValue);
        return byteAccumulator;
    }
}
