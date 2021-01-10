package de.upb.crypto.clarc.protocols.arguments.damgardtechnique;

import de.upb.crypto.clarc.protocols.CommonInput;
import de.upb.crypto.clarc.protocols.SecretInput;
import de.upb.crypto.clarc.protocols.arguments.sigma.*;
import de.upb.crypto.craco.commitment.interfaces.CommitmentPair;
import de.upb.crypto.craco.commitment.interfaces.CommitmentScheme;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.math.serialization.Representation;

import java.math.BigInteger;

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
 */
public class DamgardTechnique implements SigmaProtocol {

    protected SigmaProtocol innerProtocol;
    protected CommitmentScheme commitmentScheme;

    /**
     *
     * @param innerProtocol
     * @param commitmentScheme a commitment scheme for arbitrary bit strings (ByteArrayImplementation)
     */
    public DamgardTechnique(SigmaProtocol innerProtocol, CommitmentScheme commitmentScheme) {
        this.innerProtocol = innerProtocol;
        this.commitmentScheme = commitmentScheme;
    }

    @Override
    public DamgardAnnouncementSecret generateAnnouncementSecret(CommonInput commonInput, SecretInput secretInput) {
        AnnouncementSecret innerSecret = innerProtocol.generateAnnouncementSecret(commonInput, secretInput);
        Announcement innerAnnouncement = innerProtocol.generateAnnouncement(commonInput, secretInput, innerSecret);
        CommitmentPair commitment = commitmentScheme.commit(announcementToCommitmentPlaintext(innerAnnouncement));
        return new DamgardAnnouncementSecret(innerSecret, innerAnnouncement, commitment);
    }

    @Override
    public Announcement generateAnnouncement(CommonInput commonInput, SecretInput secretInput, AnnouncementSecret announcementSecret) {
        return new DamgardAnnouncement(((DamgardAnnouncementSecret) announcementSecret).commitment.getCommitment());
    }

    @Override
    public Challenge generateChallenge(CommonInput commonInput) {
        return innerProtocol.generateChallenge(commonInput);
    }

    @Override
    public Response generateResponse(CommonInput commonInput, SecretInput secretInput, Announcement announcement, AnnouncementSecret announcementSecret, Challenge challenge) {
        Response innerResponse = innerProtocol.generateResponse(commonInput,
                secretInput,
                ((DamgardAnnouncementSecret) announcementSecret).innerAnnouncement,
                ((DamgardAnnouncementSecret) announcementSecret).innerAnnouncementSecret,
                challenge);
        return new DamgardResponse(innerResponse, ((DamgardAnnouncementSecret) announcementSecret).innerAnnouncement, ((DamgardAnnouncementSecret) announcementSecret).commitment. getOpenValue());
    }

    @Override
    public boolean checkTranscript(CommonInput commonInput, Announcement announcement, Challenge challenge, Response response) {
        if (!commitmentScheme.verify(((DamgardAnnouncement) announcement).getCommitment(),
                ((DamgardResponse) response).getOpenValue(),
                announcementToCommitmentPlaintext(((DamgardResponse) response).getInnerAnnouncement()))) {
            return false;
        }

        return innerProtocol.checkTranscript(commonInput,
                ((DamgardResponse) response).getInnerAnnouncement(),
                challenge,
                ((DamgardResponse) response).getInnerResponse());
    }

    @Override
    public SigmaProtocolTranscript generateSimulatedTranscript(CommonInput commonInput, Challenge challenge) {
        SigmaProtocolTranscript inner = innerProtocol.generateSimulatedTranscript(commonInput, challenge);
        CommitmentPair commitmentAndOpening = commitmentScheme.commit(announcementToCommitmentPlaintext(inner.getAnnouncement()));
        return new SigmaProtocolTranscript(new DamgardAnnouncement(commitmentAndOpening.getCommitment()),
                challenge,
                new DamgardResponse(inner.getResponse(), inner.getAnnouncement(), commitmentAndOpening.getOpenValue()));
    }

    @Override
    public Announcement recreateAnnouncement(CommonInput commonInput, Representation repr) {
        return new DamgardAnnouncement(repr, commitmentScheme);
    }

    @Override
    public Challenge recreateChallenge(CommonInput commonInput, Representation repr) {
        return innerProtocol.recreateChallenge(commonInput, repr);
    }

    @Override
    public DamgardResponse recreateResponse(CommonInput commonInput, Announcement announcement, Challenge challenge, Representation repr) {
        Announcement innerAnnouncement = innerProtocol.recreateAnnouncement(commonInput, repr.obj().get("innerAnnouncement"));
        return new DamgardResponse(innerProtocol.recreateResponse(commonInput, innerAnnouncement, challenge, repr.obj().get("innerResponse")),
                innerAnnouncement,
                commitmentScheme.getOpenValue(repr.obj().get("openValue")));
    }

    @Override
    public Challenge createChallengeFromBytes(CommonInput commonInput, byte[] bytes) {
        return innerProtocol.createChallengeFromBytes(commonInput, bytes);
    }

    @Override
    public BigInteger getChallengeSpaceSize(CommonInput commonInput) {
        return innerProtocol.getChallengeSpaceSize(commonInput);
    }

    protected PlainText announcementToCommitmentPlaintext(Announcement innerAnnouncement) {
        return new ByteArrayImplementation(innerAnnouncement.getUniqueByteRepresentation());
    }
}
