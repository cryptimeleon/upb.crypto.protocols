package de.upb.crypto.clarc.protocols.arguments.sigma;

import de.upb.crypto.clarc.protocols.CommonInput;
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
    @Represented(restorer = "a")
    protected Announcement announcement;
    @Represented(restorer = "c")
    protected Challenge challenge;
    @Represented(restorer = "r")
    protected Response response;

    public SigmaProtocolTranscript(Announcement announcement, Challenge challenge, Response response) {
        this.announcement = announcement;
        this.challenge = challenge;
        this.response = response;
    }

    public SigmaProtocolTranscript(SigmaProtocol protocol, CommonInput commonInput, Representation repr) {
        new ReprUtil(this)
                .register(a -> protocol.recreateAnnouncement(a, commonInput), "a")
                .register(c -> protocol.recreateChallenge(c, commonInput), "c")
                .register(r -> protocol.recreateResponse(r, commonInput), "r")
                .deserialize(repr);
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
        return ReprUtil.serialize(this);
    }
}

