package de.upb.crypto.clarc.protocols.arguments.sigma;

import de.upb.crypto.clarc.protocols.CommonInput;
import de.upb.crypto.clarc.protocols.SecretInput;
import de.upb.crypto.clarc.protocols.arguments.InteractiveArgument;
import de.upb.crypto.clarc.protocols.arguments.InteractiveArgumentInstance;
import de.upb.crypto.math.expressions.bool.BooleanExpression;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.RepresentationRestorer;

import java.lang.reflect.Type;

public interface SigmaProtocol extends InteractiveArgument, RepresentationRestorer {
    AnnouncementSecret generateAnnouncementSecret(CommonInput commonInput, SecretInput secretInput);
    Announcement generateAnnouncement(CommonInput commonInput, SecretInput secretInput, AnnouncementSecret announcementSecret);
    Challenge generateChallenge(CommonInput commonInput);
    Response generateResponse(CommonInput commonInput, SecretInput secretInput, Announcement announcement, AnnouncementSecret announcementSecret, Challenge challenge);
    default boolean checkTranscript(CommonInput commonInput, Announcement announcement, Challenge challenge, Response response) {
        return getTranscriptCheckExpression(commonInput, announcement, challenge, response).evaluate();
    }
    default boolean checkTranscript(CommonInput commonInput, SigmaProtocolTranscript transcript) {
        return checkTranscript(commonInput, transcript.getAnnouncement(), transcript.getChallenge(), transcript.getResponse());
    }
    BooleanExpression getTranscriptCheckExpression(CommonInput commonInput, Announcement announcement, Challenge challenge, Response response);
    default BooleanExpression getTranscriptCheckExpression(CommonInput commonInput, SigmaProtocolTranscript transcript) {
        return getTranscriptCheckExpression(commonInput, transcript.getAnnouncement(), transcript.getChallenge(), transcript.getResponse());
    }

    SpecialHonestVerifierZkSimulator getSimulator();

    Announcement recreateAnnouncement(Representation repr);
    Challenge recreateChallenge(Representation repr);
    Response recreateResponse(Representation repr);
    default SigmaProtocolTranscript recreateTranscript(Representation repr) {
        return new SigmaProtocolTranscript(this, repr);
    }

    @Override
    default Object recreateFromRepresentation(Type type, Representation representation) {
        if (!(type instanceof Class))
            throw new IllegalArgumentException("Cannot recreate "+type.getTypeName());

        if (Announcement.class.isAssignableFrom((Class) type))
            return recreateAnnouncement(representation);
        if (Challenge.class.isAssignableFrom((Class) type))
            return recreateChallenge(representation);
        if (Response.class.isAssignableFrom((Class) type))
            return recreateResponse(representation);
        if (SigmaProtocolTranscript.class.isAssignableFrom((Class) type))
            return recreateTranscript(representation);

        throw new IllegalArgumentException("Cannot recreate "+type.getTypeName());
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
}
