package de.upb.crypto.clarc.protocols.arguments.sigma;

import de.upb.crypto.clarc.protocols.CommonInput;

public interface SpecialHonestVerifierZkSimulator {
    SigmaProtocolTranscript generateTranscript(CommonInput commonInput, Challenge challenge);
}
