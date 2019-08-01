package de.upb.crypto.clarc.protocols.damgardtechnique;

import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.clarc.protocols.arguments.sigma.Response;
import de.upb.crypto.craco.commitment.interfaces.OpenValue;
import de.upb.crypto.math.serialization.*;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * The DamgardResponse is used in Damgard's Technique. It consists of the commitment of an announcement, the
 * verify-value of the announcement and the original announcement.
 */
class DamgardResponse implements Response {

    private Response[] responses;
    private Announcement[] announcements;
    private OpenValue d;

    /**
     * Constructor for a DamgardResponse
     *
     * @param announcements uncommited, original announcement of Darmgard's Technique
     * @param responses     responce for given challenge
     * @param d             openvalue for committed announcement
     */
    public DamgardResponse(Announcement[] announcements, Response[] responses, OpenValue d) {
        this.responses = responses;
        this.announcements = announcements;
        this.d = d;
    }

    public Response[] getResponses() {
        return responses;
    }

    public void setResponses(Response[] responses) {
        this.responses = responses;
    }

    public Announcement[] getAnnouncements() {
        return announcements;
    }

    public void setAnnouncements(Announcement[] announcements) {
        this.announcements = announcements;
    }

    public OpenValue getD() {
        return d;
    }

    public void setD(OpenValue d) {
        this.d = d;
    }


    /**
     * The representation of this object. Used for serialization
     *
     * @return a Representation or null if the representedTypeName suffices to instantiate an equal object again
     * @see Representation
     */
    @Override
    public Representation getRepresentation() {
        ObjectRepresentation representation = new ObjectRepresentation();

        List<Representation> representationOfAnnouncements = Arrays.stream(this.announcements)
                .map(Representable::getRepresentation)
                .collect(Collectors.toList());
        representation.put("announcements", new ListRepresentation(representationOfAnnouncements));

        List<Representation> representationOfResponses = Arrays.stream(this.responses)
                .map(Representable::getRepresentation)
                .collect(Collectors.toList());
        representation.put("responses", new ListRepresentation(representationOfResponses));

        representation.put("d", new RepresentableRepresentation(d));
        return representation;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        DamgardResponse that = (DamgardResponse) o;

        // Probably incorrect - comparing Object[] arrays with Arrays.equals
        if (!Arrays.equals(responses, that.responses)) return false;
        // Probably incorrect - comparing Object[] arrays with Arrays.equals
        if (!Arrays.equals(announcements, that.announcements)) return false;
        return d != null ? d.equals(that.d) : that.d == null;
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(responses);
        result = 31 * result + Arrays.hashCode(announcements);
        result = 31 * result + (d != null ? d.hashCode() : 0);
        return result;
    }
}
