package de.upb.crypto.clarc.protocols.arguments.sigma;

import de.upb.crypto.clarc.protocols.CommonInput;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

/**
 * A transcript contains the messages exchanged during the execution of a three way protocol.
 * These are announcement, challenge and response. Announcement and Response are send by the Prover to the Verifier, the
 * challenge from the Verifier to the Prover.
 */
public class SigmaProtocolTranscript implements Representable {
    protected Announcement announcement;
    protected Challenge challenge;
    protected Response response;

    public SigmaProtocolTranscript(Announcement announcement, Challenge challenge, Response response) {
        this.announcement = announcement;
        this.challenge = challenge;
        this.response = response;
    }

    public SigmaProtocolTranscript(SigmaProtocol protocol, CommonInput commonInput, Representation repr) {
        announcement = protocol.recreateAnnouncement(commonInput, repr.obj().get("a"));
        challenge = protocol.recreateChallenge(commonInput, repr.obj().get("c"));
        response = protocol.recreateResponse(commonInput, announcement, challenge, repr.obj().get("r"));
    }

    public Announcement getAnnouncement() {
        return announcement;
    }

    public Challenge getChallenge() {
        return challenge;
    }

    public Response getResponse() {
        return response;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("a", announcement.getRepresentation());
        repr.put("c", challenge.getRepresentation());
        repr.put("r", response.getRepresentation());
        return repr;
    }
}

