package de.upb.crypto.clarc.protocols.arguments.sigma;

import de.upb.crypto.clarc.protocols.CommonInput;
import de.upb.crypto.clarc.protocols.SecretInput;
import de.upb.crypto.clarc.protocols.arguments.InteractiveArgument;
import de.upb.crypto.math.expressions.bool.BooleanExpression;
import de.upb.crypto.math.serialization.Representation;

public class SigmaProtocolProverInstance extends SigmaProtocolInstance {
    protected State state;

    protected enum State {
        NOTHING,
        SENT_ANNOUNCEMENT,
        SENT_RESPONSE
    }

    public SigmaProtocolProverInstance(SigmaProtocol protocol, CommonInput commonInput, SecretInput secretInput) {
        super(protocol, commonInput, secretInput);
    }

    @Override
    public BooleanExpression getAcceptanceExpression() {
        throw new UnsupportedOperationException("The prover cannot check for acceptance.");
    }

    @Override
    public String getRoleName() {
        return InteractiveArgument.PROVER_ROLE;
    }

    @Override
    public Representation nextMessage(Representation received) {
        switch (state) {
            case NOTHING:
                announcementSecret = protocol.generateAnnouncementSecret(commonInput, secretInput);
                announcement = protocol.generateAnnouncement(commonInput, secretInput, announcementSecret);
                state = State.SENT_ANNOUNCEMENT;
                return announcement.getRepresentation();
            case SENT_ANNOUNCEMENT:
                challenge = protocol.recreateChallenge(received);
                state = State.SENT_RESPONSE;
                response = protocol.generateResponse(commonInput, secretInput, announcement, announcementSecret, challenge);
                return response.getRepresentation();
            case SENT_RESPONSE:
                return null; //done with the protocol. We actually should not have received any message anymore.
            default:
                throw new IllegalStateException("Unexpected state for Sigma protocol instance: "+state.toString());
        }
    }

    @Override
    public boolean hasTerminated() {
        return state == State.SENT_RESPONSE;
    }
}
