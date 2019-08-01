package de.upb.crypto.clarc.protocols.schnorr;

import de.upb.crypto.clarc.protocols.CommonInput;
import de.upb.crypto.clarc.protocols.arguments.sigma.Challenge;
import de.upb.crypto.clarc.protocols.arguments.sigma.SigmaProtocolTranscript;
import de.upb.crypto.clarc.protocols.arguments.sigma.SpecialHonestVerifierZkSimulator;

public class SchnorrSimulator implements SpecialHonestVerifierZkSimulator {
    protected SchnorrProtocol protocol;

    public SchnorrSimulator(SchnorrProtocol protocol) {
        this.protocol = protocol;
    }

    @Override
    public SigmaProtocolTranscript generateTranscript(CommonInput commonInput, Challenge challenge) {
        return null; //TODO impl
    }
}
