package de.upb.crypto.clarc.protocols.arguments.sigma;

import de.upb.crypto.clarc.protocols.CommonInput;
import de.upb.crypto.clarc.protocols.SecretInput;
import de.upb.crypto.clarc.protocols.arguments.InteractiveArgument;
import de.upb.crypto.clarc.protocols.arguments.InteractiveArgumentInstance;
import de.upb.crypto.math.expressions.bool.BooleanExpression;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.RepresentationRestorer;

import java.lang.reflect.Type;

public interface SigmaProtocol extends InteractiveArgument {
    AnnouncementSecret generateAnnouncementSecret(CommonInput commonInput, SecretInput secretInput);
    Announcement generateAnnouncement(CommonInput commonInput, SecretInput secretInput, AnnouncementSecret announcementSecret);
    Challenge generateChallenge(CommonInput commonInput);
    Response generateResponse(CommonInput commonInput, SecretInput secretInput, Announcement announcement, AnnouncementSecret announcementSecret, Challenge challenge);
    boolean checkTranscript(CommonInput commonInput, Announcement announcement, Challenge challenge, Response response);
    default boolean checkTranscript(CommonInput commonInput, SigmaProtocolTranscript transcript) {
        return checkTranscript(commonInput, transcript.getAnnouncement(), transcript.getChallenge(), transcript.getResponse());
    }

    SigmaProtocolTranscript generateSimulatedTranscript(CommonInput commonInput, Challenge challenge);

    Announcement recreateAnnouncement(CommonInput commonInput, Representation repr);
    Challenge recreateChallenge(CommonInput commonInput, Representation repr);
    Response recreateResponse(CommonInput commonInput, Announcement announcement, Challenge challenge, Representation repr);
    default SigmaProtocolTranscript recreateTranscript(Representation repr, CommonInput commonInput) {
        return new SigmaProtocolTranscript(this, commonInput, repr);
    }

    @Override
    default String getFirstMessageRole() {
        return InteractiveArgument.PROVER_ROLE;
    }

    @Override
    default InteractiveArgumentInstance instantiateProtocol(String role, CommonInput commonInput, SecretInput secretInput) {
        return PROVER_ROLE.equals(role) ? new SigmaProtocolProverInstance(this, commonInput, secretInput) :
                VERIFIER_ROLE.equals(role) ? new SigmaProtocolVerifierInstance(this, commonInput) : null;
    }

    default SigmaProtocolProverInstance getProverInstance(CommonInput commonInput, SecretInput secretInput) {
        return new SigmaProtocolProverInstance(this, commonInput, secretInput);
    }

    default SigmaProtocolVerifierInstance getVerifierInstance(CommonInput commonInput) {
        return new SigmaProtocolVerifierInstance(this, commonInput);
    }
}
