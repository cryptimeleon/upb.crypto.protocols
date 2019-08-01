package de.upb.crypto.clarc.protocols.simulator;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.clarc.protocols.arguments.sigma.Challenge;
import de.upb.crypto.clarc.protocols.arguments.sigma.Response;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;

import java.util.Arrays;
import java.util.Objects;

/**
 * A general representation of a transcript for a sigma protocol
 */
public class SigmaProtocolTranscript implements de.upb.crypto.clarc.protocols.arguments.sigma.SigmaProtocolTranscript {
    @RepresentedArray(elementRestorer =
    @Represented(structure = "protocol", recoveryMethod = Announcement.RECOVERY_METHOD))
    private Announcement[] announcement;
    @Represented(structure = "protocol", recoveryMethod = Challenge.RECOVERY_METHOD)
    private Challenge challege;
    @RepresentedArray(elementRestorer =
    @Represented(structure = "protocol", recoveryMethod = Response.RECOVERY_METHOD))
    private Response[] responses;
    @Represented
    private SigmaProtocol protocol;


    /**
     * @param announcement for the transcript
     * @param challege     given to simulator
     * @param responses    for the transcript
     * @param protocol     used to recreate the trnascript elements
     */
    public SigmaProtocolTranscript(Announcement[] announcement, Challenge challege, Response[] responses,
                                   SigmaProtocol protocol) { //TODO remove protocol from parameters.
        this.announcement = announcement;
        this.challege = challege;
        this.responses = responses;
        this.protocol = protocol;
    }

    public SigmaProtocolTranscript(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    @Override
    public Announcement[] getAnnouncements() {
        return this.announcement;
    }

    @Override
    public Challenge getChallenge() {
        return this.challege;
    }

    @Override
    public Response[] getResponses() {
        return this.responses;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public SigmaProtocol getProtocol() {
        return protocol;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SigmaProtocolTranscript that = (SigmaProtocolTranscript) o;
        return Arrays.equals(announcement, that.announcement) &&
                Objects.equals(challege, that.challege) &&
                Arrays.equals(getResponses(), that.getResponses()) &&
                Objects.equals(protocol, that.protocol);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(challege, protocol);
        result = 31 * result + Arrays.hashCode(announcement);
        result = 31 * result + Arrays.hashCode(getResponses());
        return result;
    }
}
