package de.upb.crypto.clarc.protocols.simulator;

import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * A transcript contains the messages exchanged during the execution of a three way protocol.
 * These are announcement, challenge and response. Announcement and Response are send by the Prover to the Verifier, the
 * challenge from the Verifier to the Prover.
 */
public interface Transcript extends StandaloneRepresentable {

    /**
     * @return the announcement stored in the transcript.
     */
    Announcement[] getAnnouncements();

    /**
     * @return the challenge stored in the transcript.
     */
    Challenge getChallenge();

    /**
     * @return the response stored in the transcript.
     */
    Response[] getResponses();
}

