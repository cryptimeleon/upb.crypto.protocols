package de.upb.crypto.clarc.protocols.arguments;

import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.clarc.protocols.arguments.sigma.Challenge;
import de.upb.crypto.clarc.protocols.arguments.sigma.Response;
import de.upb.crypto.math.serialization.Representation;

/**
 * Interface for the execution of a three way argument of knowledge protocol
 * <p>
 * Intended protocol execution: <br>
 * prover: {@link InteractiveThreeWayAoK#generateAnnouncements} <br>
 * verifier: {@link InteractiveThreeWayAoK#chooseChallenge} <br>
 * prover: {@link InteractiveThreeWayAoK#generateResponses} <br>
 * verifier: {@link InteractiveThreeWayAoK#verify}
 * </p>
 */
public interface InteractiveThreeWayAoK extends InteractiveArgument {
    /**
     * checks if the sigma protocol is fulfilled using the witnesses stored inside the protocol
     *
     * @return true, if the witnesses fulfill the problem equations, false otherwise
     */
    boolean isFulfilled();

    /**
     * This is an algorithm for the creation of an announcement that chooses the randomness used internally. The
     * randomness
     * is stored internally nd will be used in the response.
     * Important: It is strictly recommended to use the generateResponse-Algorithm without randomness as input
     * parameter!
     *
     * @return an announcement for the protocol
     */
    Announcement[] generateAnnouncements();

    /**
     * Chooses a challenge for the protocol according to the distributions defined in the protocol itself
     *
     * @return the challenge
     */
    Challenge chooseChallenge();

    /**
     * This algorithm generates an response. IMPORTANT: It works only, when the announcement is generated using NO
     * EXTERNAL RANDOMNESS!
     *
     * @param challenge the challenge chosen by the verifier
     * @return a response corresponding to the given challenge using the randomness saved locally.
     */
    Response[] generateResponses(Challenge challenge);

    /**
     * Verifies, if the given announcement, challenge and response add up to a valid transcript.
     *
     * @param announcements used for verification
     * @param challenge     used for verification
     * @param responses     used for verification
     * @return true iff announcement, challenge and response are valid, false otherwise
     */
    boolean verify(Announcement[] announcements, Challenge challenge, Response[] responses);

    /**
     * This method restores a single serialized announcement
     *
     * @param representation of the announcement array
     * @return the restored announcement array
     */
    Announcement recreateAnnouncement(Representation representation);

    /**
     * This method restores the serialized array of challenge
     *
     * @param representation of the challenge
     * @return the restored challenge
     */
    Challenge recreateChallenge(Representation representation);

    Challenge createChallengeFromByteArray(byte[] integer);

    /**
     * This method restores a single serialized response
     *
     * @param representation of the announcement array
     * @return the restored responses array
     */
    Response recreateResponse(Representation representation);
}
