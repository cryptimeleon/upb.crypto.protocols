package de.upb.crypto.clarc.protocols.arguments.sigma;

import de.upb.crypto.clarc.protocols.CommonInput;
import de.upb.crypto.clarc.protocols.SecretInput;
import de.upb.crypto.clarc.protocols.arguments.InteractiveArgument;
import de.upb.crypto.math.expressions.bool.BooleanExpression;
import de.upb.crypto.math.serialization.Representation;

public class SigmaProtocolVerifierInstance extends SigmaProtocolInstance {
    protected State state;

    protected enum State {
        NOTHING,
        SENT_CHALLENGE,
        RECEIVED_RESPONSE
    }

    public SigmaProtocolVerifierInstance(SigmaProtocol protocol, CommonInput commonInput) {
        super(protocol, commonInput);
    }

    @Override
    public String getRoleName() {
        return InteractiveArgument.VERIFIER_ROLE;
    }

    @Override
    public Representation nextMessage(Representation received) {
        switch (state) {
            case NOTHING: //receiving announcement
                announcement = protocol.recreateAnnouncement(received);
                challenge = protocol.generateChallenge(commonInput);
                state = State.SENT_CHALLENGE;
                return announcement.getRepresentation();
            case SENT_CHALLENGE: //receiving response
                response = protocol.recreateResponse(received);
                state = State.RECEIVED_RESPONSE;
                return null; //done
            case RECEIVED_RESPONSE:
                return null; //done with the protocol. We actually should not have received any message anymore.
            default:
                throw new IllegalStateException("Unexpected state for Sigma protocol instance: "+state.toString());
        }
    }

    @Override
    public boolean hasTerminated() {
        return state == State.RECEIVED_RESPONSE;
    }

    @Override
    public BooleanExpression getAcceptanceExpression() {
        return protocol.getTranscriptCheckExpression(commonInput, announcement, challenge, response);
    }
}
