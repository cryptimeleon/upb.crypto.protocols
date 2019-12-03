package de.upb.crypto.clarc.protocols.damgardtechnique;

import de.upb.crypto.clarc.protocols.CommonInput;
import de.upb.crypto.clarc.protocols.arguments.sigma.Challenge;
import de.upb.crypto.clarc.protocols.arguments.sigma.SigmaProtocolTranscript;
import de.upb.crypto.clarc.protocols.arguments.sigma.SpecialHonestVerifierZkSimulator;
import de.upb.crypto.craco.commitment.interfaces.Commitment;
import de.upb.crypto.craco.commitment.interfaces.CommitmentPair;

public class DamgardSimulator implements SpecialHonestVerifierZkSimulator {
    protected DamgardTechnique protocol;
    protected SpecialHonestVerifierZkSimulator innerSimulator;

    public DamgardSimulator(DamgardTechnique protocol) {
        this.protocol = protocol;
        this.innerSimulator = protocol.innerProtocol.getSimulator();
    }

    @Override
    public SigmaProtocolTranscript generateTranscript(CommonInput commonInput, Challenge challenge) {
        SigmaProtocolTranscript inner = innerSimulator.generateTranscript(commonInput, challenge);
        CommitmentPair commitmentAndOpening = protocol.commitmentScheme.commit(protocol.announcementToCommitmentPlaintext(inner.getAnnouncement()));
        return new SigmaProtocolTranscript(new DamgardAnnouncement(commitmentAndOpening.getCommitment()),
                challenge,
                new DamgardResponse(inner.getResponse(), inner.getAnnouncement(), commitmentAndOpening.getOpenValue()));
    }
}
