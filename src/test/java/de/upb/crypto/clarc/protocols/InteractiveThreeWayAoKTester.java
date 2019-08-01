package de.upb.crypto.clarc.protocols;

import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.clarc.protocols.arguments.sigma.Challenge;
import de.upb.crypto.clarc.protocols.arguments.sigma.Response;
import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class InteractiveThreeWayAoKTester {
    /**
     * Positive test checking that for a correct protocol execution the verifier accepts. An interactive correct
     * protocol execution with prover and verifier is performed. In the end it is checked that verify returns true.
     * The test is checking the protocol execution with external randomness.
     *
     * @param protocolProver   InteractiveThreeWayAoK with witnesses to prove knowledge
     * @param protocolVerifier InteractiveThreeWayAoK without witnesses (nulled) to be convinced of knowledge
     */
    public static void protocolExecutionInternalRandomnessTest(InteractiveThreeWayAoK protocolProver,
                                                               InteractiveThreeWayAoK protocolVerifier) {
        Announcement[] a = protocolProver.generateAnnouncements();
        Challenge c = protocolVerifier.chooseChallenge();
        Response[] r = protocolProver.generateResponses(c);
        assertTrue(protocolVerifier.verify(a, c, r));
    }

    /**
     * Negative test checking that for a correct protocol execution the verifier does not accepts. An interactive
     * incorrect protocol execution with prover and verifier is performed.
     * In the end it is checked that verify returns false.
     * The test is checking the protocol execution with internal randomness.
     *
     * @param protocolProver   InteractiveThreeWayAoK with witnesses to prove knowledge
     * @param protocolVerifier InteractiveThreeWayAoK without witnesses (nulled) to be convinced of knowledge
     */
    public static void protocolNegativeExecutionInternalRandomnessTest(InteractiveThreeWayAoK protocolProver,
                                                                       InteractiveThreeWayAoK protocolVerifier) {
        Announcement[] a = protocolProver.generateAnnouncements();
        Challenge c = protocolVerifier.chooseChallenge();
        Response[] r = protocolProver.generateResponses(c);
        assertFalse(protocolVerifier.verify(a, c, r));
    }


    /**
     * This negative test checks cases where the verify method is called with not matching parameters and therefore
     * should return false for internal randomness.
     * It checks that protocol executions decline (return false for verify) where at least the challenge, the response
     * or the announcement do not match.
     * To achieve this, one correct protocol execution is done creating Announcement a, Challenge c and Response r. Then
     * an inequal Challenge c2 is created for checking not matching challenges. Furthermore, a second announcement with
     * different (internal) randomness created and a second response is calculated for this second announcement. Then
     * all combinations of incorrect protocol executions are checked for declining.
     * All is done for the same problems.
     *
     * @param protocolProver       InteractiveThreeWayAoK with witnesses to prove knowledge
     * @param secondProtocolProver Different InteractiveThreeWayAoK from first InteractiveThreeWayAoK with witnesses to
     *                             prove knowledge. This allows checking negative cases with two different
     *                             prover-protocols.
     * @param protocolVerifier     InteractiveThreeWayAoK without witnesses (nulled) to be convinced of knowledge
     */
    public static void protocolExecutionInternalRandomnessNegativeTest(InteractiveThreeWayAoK protocolProver,
                                                                       InteractiveThreeWayAoK secondProtocolProver,
                                                                       InteractiveThreeWayAoK protocolVerifier) {
        Announcement[] a = protocolProver.generateAnnouncements();
        Challenge c = protocolVerifier.chooseChallenge();
        Response[] r = protocolProver.generateResponses(c);

        // choose different challenge
        Challenge c2;
        do {
            c2 = protocolVerifier.chooseChallenge();
        } while (c2.equals(c));
        // create different announcement (using different internal randomness; else the announcement would be the same)
        Announcement[] a2;
        do {
            a2 = secondProtocolProver.generateAnnouncements();
        } while (Arrays.equals(a, a2));
        // calculate second response
        Response[] r2 = secondProtocolProver.generateResponses(c);
        // check all incorrect protocol executions
        try {
            assertFalse(protocolVerifier.verify(a, c2, r));
        } catch (RuntimeException e) {
        }
        try {
            assertFalse(protocolVerifier.verify(a2, c2, r));
        } catch (RuntimeException e) {
        }
        try {
            assertFalse(protocolVerifier.verify(a, c2, r2));
        } catch (RuntimeException e) {
        }
        try {
            assertFalse(protocolVerifier.verify(a, c, r2));
        } catch (RuntimeException e) {
        }
        try {
            assertFalse(protocolVerifier.verify(a2, c2, r2));
        } catch (RuntimeException e) {
        }
        try {
            assertFalse(protocolVerifier.verify(a2, c, r));
        } catch (RuntimeException e) {
        }
    }

    /**
     * This test checks the representation usage within the execution.
     * This test performs a correct protocol execution where announcement, challenge and response are serialized and
     * deserialized before verification. If at least one serialization and deserialization does not work correctly, this
     * test fails.
     */
    public static void representationForProtocolExecutionTest(InteractiveThreeWayAoK protocolProver,
                                                              InteractiveThreeWayAoK protocolVerifier) {

        // test representation of the announcement
        Announcement[] a = protocolProver.generateAnnouncements();

        for (Announcement announcement : a) {
            assertEquals(announcement, protocolProver.recreateAnnouncement(announcement.getRepresentation()),
                    "Announcement recreation failed");
        }

        // test representation of the challenge
        Challenge c = protocolVerifier.chooseChallenge();
        Challenge c2 = protocolProver.recreateChallenge(c.getRepresentation());
        assertEquals(c, c2);

        // test representation of the response
        Response[] r = protocolProver.generateResponses(c);
        for (Response response : r) {
            assertEquals(response, protocolProver.recreateResponse(response.getRepresentation()),
                    "Response recreation failed");
        }

        // verify that execution is still correct in recreated values
        for (int i=0;i<a.length;i++)
            a[i] = protocolProver.recreateAnnouncement(a[i].getRepresentation());
        for (int i=0;i<r.length;i++)
            r[i] = protocolProver.recreateResponse(r[i].getRepresentation());
        assertTrue(protocolVerifier.verify(a, c2, r));
    }

    /**
     * This test checks whether the recreation mehtods for {@link Announcement}, {@link Challenge} and {@link Response}
     * work for a correct protocol-execution.
     *
     * @param protocolProver   InteractiveThreeWayAoK with witnesses to prove knowledge
     * @param protocolVerifier InteractiveThreeWayAoK without witnesses (nulled) to be convinced of knowledge
     */
    public static void recreateTest(InteractiveThreeWayAoK protocolProver,
                                    InteractiveThreeWayAoK protocolVerifier) {

        // test announcement recreation
        Announcement[] announcements = protocolProver.generateAnnouncements();
        Representation[] announcementRepresentations =
                Arrays.stream(announcements).map(Representable::getRepresentation).toArray(Representation[]::new);
        announcements = Arrays.stream(announcementRepresentations)
                .map(protocolProver::recreateAnnouncement)
                .toArray(Announcement[]::new);

        // test challenge recreation
        Challenge challenge = protocolVerifier.chooseChallenge();
        Representation challengeRepresentation = challenge.getRepresentation();
        challenge = protocolVerifier.recreateChallenge(challengeRepresentation);

        // test announcement recreation
        Response[] responses = protocolProver.generateResponses(challenge);
        Representation[] responseRepresentations =
                Arrays.stream(responses).map(Representable::getRepresentation).toArray(Representation[]::new);
        responses = Arrays.stream(responseRepresentations)
                .map(protocolProver::recreateResponse)
                .toArray(Response[]::new);
        assertTrue(protocolVerifier.verify(announcements, challenge, responses));
    }

}
