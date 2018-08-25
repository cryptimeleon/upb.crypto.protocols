package de.upb.crypto.clarc.protocols.damgardtechnique;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.arguments.ZeroKnowledgeThreeWayAoK;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.commitment.interfaces.CommitmentPair;
import de.upb.crypto.craco.commitment.interfaces.CommitmentScheme;
import de.upb.crypto.craco.commitment.interfaces.CommitmentSchemePublicParameters;
import de.upb.crypto.craco.commitment.interfaces.OpenValue;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;

import java.util.Arrays;

/**
 * This class provides Damgard's Technique. Damgard's Technique is a construction to improve Sigma-Protocols in order to
 * provide security against concurrent adversaries. The resulting protocol is a 'Concurrent black-box zero knowledge
 * three-way interactive argument of knowledge'.
 * Damgard's Technique is applied on a given Sigma-Protocol. A given commitment scheme is used to achieve the security
 * improvement by changing the original given Sigma-Protocol in the following way:
 * <p>
 * 1.) Instead of sending the announcement the protocol sends the commitment of the announcement.
 * 2.) The last message additionally contains the original announcement and the verify-value of the commitment of the
 * announcement. These information are then used in the verify to check validity of the commitment as well as the
 * original verification from the Sigma-Protocol.
 * <p>
 * The result of Damgard's Technique is a 'Concurrent black-box zero knowledge three-way interactive argument of
 * knowledge'.
 * Therefore the announcement and Response are extended in such a way that they contain the needed information.
 */
public class DamgardTechnique implements ZeroKnowledgeThreeWayAoK {

    @Represented
    private SigmaProtocol protocol;
    @Represented
    private CommitmentScheme commitmentScheme;
    @Represented
    private CommitmentPair commitPair = null;
    @RepresentedArray(elementRestorer = @Represented(structure = "protocol", recoveryMethod = Announcement
            .RECOVERY_METHOD))
    private Announcement[] announcements = null;

    /**
     * Constructor for a Sigma Protocol using Damgard's Technique
     *
     * @param protocol         {@link SigmaProtocol} used in Damgard`s Technique
     * @param commitmentScheme {@link CommitmentScheme} for a single message used in Damgard's Technique; Prover and
     *                         Verifier need to use the
     *                         same {@link CommitmentScheme} and {@link CommitmentSchemePublicParameters}
     */
    public DamgardTechnique(SigmaProtocol protocol, CommitmentScheme commitmentScheme) {
        super();
        this.protocol = protocol;
        this.commitmentScheme = commitmentScheme;
    }

    /**
     * Constructor for a Sigma Protocol using Damgard's Technique from a {@link Representation}
     *
     * @param representation {@link Representation} of a {@link DamgardTechnique}-instance.
     */
    public DamgardTechnique(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    /**
     * The representation of this object. Used for serialization
     *
     * @return a Representation or null if the representedTypeName suffices to instantiate an equal object again
     * @see Representation
     */
    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean isFulfilled() {
        return protocol.isFulfilled();
    }

    /**
     * Generates the announcements for a prover and returns the commit-value for the announcements.
     * This is an algorithm for the creation of an announcement that chooses the randomness used internally. The
     * randomness is stored internally nd will be used in the response.
     * <p>
     * Important: It is strictly recommended to use the generateResponse-Algorithm without randomness as input
     * parameter!
     *
     * @return Commit-value for the generated Announcements.
     */
    @Override
    public Announcement[] generateAnnouncements() {
        announcements = protocol.generateAnnouncements();
        commitPair = commitmentScheme.commit(getAnnouncementPlainText(announcements));

        return new DamgardAnnouncement[]{new DamgardAnnouncement(commitPair.getCommitmentValue())};
    }


    /**
     * Chooses the challenge for an announcement. The challenge is chosen by the underlying Sigma-protocol.
     *
     * @return Challenge for announcement.
     */
    @Override
    public Challenge chooseChallenge() {
        return protocol.chooseChallenge();
    }

    /***
     * This algorithm generates an response.
     * @param challenge the challenge chosen by the verifier
     * @return a response corresponding to the given challenge using the randomness saved locally.
     */
    @Override
    public Response[] generateResponses(Challenge challenge) {
        return new DamgardResponse[]{new DamgardResponse(announcements, protocol.generateResponses
                (challenge), commitPair.getOpenValue())};
    }

    /**
     * This algorithm verifies that the opened message of the committed value equals the uncommitted announcements and
     * that the response matches the given challenge. Only when both cases are true, the algorithm returns true; else
     * false.
     *
     * @param announcements commitvalue for original announcements
     * @param challenge     challenge for announcements
     * @param responses     response corresponding to the given challenge
     *
     * @return return true only if the opened message of the committed value equals the uncommitted announcements and
     *         that the response matches the given challenge; else: false.
     */
    @Override
    public boolean verify(Announcement[] announcements, Challenge challenge, Response[] responses) {
        if (announcements.length != 1 || !(announcements[0] instanceof DamgardAnnouncement)) {
            throw new IllegalArgumentException("The announcement must be a Damgard announcement of size 1!");
        }
        if (responses.length != 1 || (!(responses[0] instanceof DamgardResponse))) {
            throw new IllegalArgumentException("The response must be a Damgard response of size 1");
        }
        DamgardAnnouncement damgardAnnouncement = (DamgardAnnouncement) announcements[0];
        DamgardResponse damgardResponse = (DamgardResponse) responses[0];
        boolean correctCommitment = commitmentScheme.verify(damgardAnnouncement.getCommitmentValue(), damgardResponse
                        .getD(),
                getAnnouncementPlainText(damgardResponse.getAnnouncements()));
        boolean correctVerify = protocol.verify(damgardResponse.getAnnouncements(), challenge,
                damgardResponse.getResponses());
        return correctCommitment && correctVerify;
    }

    /**
     * This method restores the serialized array of announcements
     *
     * @param representation of the announcement array
     *
     * @return the restored announcement array
     */
    @Override
    public Announcement recreateAnnouncement(Representation representation) {
        return new DamgardAnnouncement(representation);
    }

    /**
     * This method restores the serialized array of challenge
     *
     * @param representation of the challenge
     *
     * @return the restored challenge
     */
    @Override
    public Challenge recreateChallenge(Representation representation) {
        return this.protocol.recreateChallenge(representation);
    }

    @Override
    public Challenge createChallengeFromByteArray(byte[] integer) {
        return protocol.createChallengeFromByteArray(integer);
    }

    /**
     * This method restores the serialized array of responses
     *
     * @param representation of the announcement array
     *
     * @return the restored responses array
     */
    @Override
    public Response recreateResponse(Representation representation) {
        ObjectRepresentation objRepr = representation.obj();

        Announcement[] announcementInResponse = objRepr.get("announcements").list()
                                                       .stream()
                                                       .map(protocol::recreateAnnouncement)
                                                       .toArray(Announcement[]::new);

        Response[] responses = objRepr.get("responses").list()
                                      .stream()
                                      .map(protocol::recreateResponse)
                                      .toArray(Response[]::new);

        OpenValue d = (OpenValue) objRepr.get("d").repr().recreateRepresentable();
        return new DamgardResponse(announcementInResponse, responses, d);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((protocol == null) ? 0 : protocol.hashCode());
        result = prime * result + ((commitmentScheme == null) ? 0 : commitmentScheme.hashCode());
        result = prime * result + ((commitPair == null) ? 0 : commitPair.hashCode());
        result = prime * result + ((announcements == null) ? 0 : Arrays.hashCode(announcements));
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        DamgardTechnique other = (DamgardTechnique) obj;
        if (protocol == null) {
            if (other.protocol != null)
                return false;
        } else if (!protocol.equals(other.protocol))
            return false;
        if (commitmentScheme == null) {
            if (other.commitmentScheme != null)
                return false;
        } else if (!commitmentScheme.equals(other.commitmentScheme))
            return false;
        if (commitPair == null) {
            if (other.commitPair != null)
                return false;
        } else if (!commitPair.equals(other.commitPair))
            return false;
        if (announcements == null) {
            return other.announcements == null;
        } else return Arrays.equals(announcements, other.announcements);
    }

    /**
     * Internal casting method to generate a {@link PlainText} conforming a
     * {@link de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation} of the {@link SigmaProtocol}'s
     * {@link Announcement}
     *
     * @param announcements the {@link SigmaProtocol}'s {@link Announcement}
     *
     * @return {@link PlainText} of the {@link SigmaProtocol}'s {@link Announcement}
     */
    private PlainText getAnnouncementPlainText(Announcement[] announcements) {
        return new MessageBlock(announcements);
    }
}
