package de.upb.crypto.clarc.protocols.arguments.sigma.schnorr;

import de.upb.crypto.clarc.protocols.CommonInput;
import de.upb.crypto.clarc.protocols.SecretInput;
import de.upb.crypto.clarc.protocols.arguments.sigma.*;
import de.upb.crypto.clarc.protocols.arguments.sigma.schnorr.variables.SchnorrVariableAssignment;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;

public abstract class SendThenDelegateProtocol implements SigmaProtocol {

    protected abstract SendThenDelegateFragment.ProverSpec provideProverSpec(CommonInput commonInput, SecretInput secretInput, SendThenDelegateFragment.ProverSpecBuilder builder);
    protected abstract SendThenDelegateFragment.SendFirstValue recreateSendFirstValue(CommonInput commonInput, Representation repr);
    protected abstract SendThenDelegateFragment.SendFirstValue simulateSendFirstValue(CommonInput commonInput);

    protected abstract SendThenDelegateFragment.SubprotocolSpec provideSubprotocolSpec(CommonInput commonInput, SendThenDelegateFragment.SendFirstValue sendFirstValue, SendThenDelegateFragment.SubprotocolSpecBuilder builder);

    protected abstract boolean provideAdditionalCheck(CommonInput commonInput, SendThenDelegateFragment.SendFirstValue sendFirstValue);

    @Override
    public AnnouncementSecret generateAnnouncementSecret(CommonInput commonInput, SecretInput secretInput) {
        TopLevelSchnorrFragment fragment = new TopLevelSchnorrFragment(commonInput, secretInput);
        AnnouncementSecret fragmentAnnouncementSecret = fragment.generateAnnouncementSecret(SchnorrVariableAssignment.EMPTY);

        return new SchnorrAnnouncementSecret(fragment, fragmentAnnouncementSecret);
    }

    @Override
    public Announcement generateAnnouncement(CommonInput commonInput, SecretInput secretInput, AnnouncementSecret announcementSecret) {
        SchnorrAnnouncementSecret announcementSecret1 = (SchnorrAnnouncementSecret) announcementSecret;
        return announcementSecret1.fragment.generateAnnouncement(SchnorrVariableAssignment.EMPTY, announcementSecret1.fragmentAnnouncementSecret, SchnorrVariableAssignment.EMPTY);
    }

    @Override
    public abstract SchnorrChallenge generateChallenge(CommonInput commonInput);

    @Override
    public Response generateResponse(CommonInput commonInput, SecretInput secretInput, Announcement announcement, AnnouncementSecret announcementSecret, Challenge challenge) {
        SchnorrAnnouncementSecret announcementSecret1 = (SchnorrAnnouncementSecret) announcementSecret;
        return announcementSecret1.fragment.generateResponse(SchnorrVariableAssignment.EMPTY, announcementSecret1.fragmentAnnouncementSecret, challenge);
    }

    @Override
    public boolean checkTranscript(CommonInput commonInput, Announcement announcement, Challenge challenge, Response response) {
        return ((SchnorrAnnouncement) announcement).fragment.checkTranscript(((SchnorrAnnouncement) announcement).fragmentAnnouncement, challenge, response, SchnorrVariableAssignment.EMPTY);
    }

    @Override
    public SigmaProtocolTranscript generateSimulatedTranscript(CommonInput commonInput, Challenge challenge) {
        TopLevelSchnorrFragment fragment = new TopLevelSchnorrFragment(commonInput);
        return fragment.generateSimulatedTranscript(challenge, SchnorrVariableAssignment.EMPTY);
    }

    @Override
    public Announcement recreateAnnouncement(CommonInput commonInput, Representation repr) {
        TopLevelSchnorrFragment fragment = new TopLevelSchnorrFragment(commonInput);
        return new SchnorrAnnouncement(fragment, fragment.recreateAnnouncement(repr));
    }

    @Override
    public Challenge recreateChallenge(CommonInput commonInput, Representation repr) {
        return new SchnorrChallenge(repr);
    }

    @Override
    public Response recreateResponse(CommonInput commonInput, Announcement announcement, Challenge challenge, Representation repr) {
        return ((SchnorrAnnouncement) announcement).fragment.recreateResponse(((SchnorrAnnouncement) announcement).fragmentAnnouncement, repr);
    }

    public static class SchnorrAnnouncementSecret implements AnnouncementSecret {
        public final TopLevelSchnorrFragment fragment;
        public final AnnouncementSecret fragmentAnnouncementSecret;

        public SchnorrAnnouncementSecret(TopLevelSchnorrFragment fragment, AnnouncementSecret fragmentAnnouncementSecret) {
            this.fragment = fragment;
            this.fragmentAnnouncementSecret = fragmentAnnouncementSecret;
        }
    }

    public static class SchnorrAnnouncement implements Announcement {
        public final SchnorrFragment fragment;
        public final Announcement fragmentAnnouncement;

        public SchnorrAnnouncement(SchnorrFragment fragment, Announcement fragmentAnnouncement) {
            this.fragment = fragment;
            this.fragmentAnnouncement = fragmentAnnouncement;
        }

        @Override
        public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
            return fragmentAnnouncement.updateAccumulator(accumulator);
        }

        @Override
        public Representation getRepresentation() {
            return fragmentAnnouncement.getRepresentation();
        }
    }

    public class TopLevelSchnorrFragment extends SendThenDelegateFragment {
        public final CommonInput commonInput;
        public final SecretInput secretInput;

        public TopLevelSchnorrFragment(CommonInput commonInput, SecretInput secretInput) {
            this.commonInput = commonInput;
            this.secretInput = secretInput;
        }

        public TopLevelSchnorrFragment(CommonInput commonInput) {
            this(commonInput, null);
        }

        @Override
        protected ProverSpec provideProverSpec(SchnorrVariableAssignment outerWitnesses, ProverSpecBuilder builder) {
            return SendThenDelegateProtocol.this.provideProverSpec(commonInput, secretInput, builder);
        }

        @Override
        protected SendFirstValue recreateSendFirstValue(Representation repr) {
            return SendThenDelegateProtocol.this.recreateSendFirstValue(commonInput, repr);
        }

        @Override
        protected SendFirstValue simulateSendFirstValue() {
            return SendThenDelegateProtocol.this.simulateSendFirstValue(commonInput);
        }

        @Override
        protected SubprotocolSpec provideSubprotocolSpec(SendFirstValue sendFirstValue, SubprotocolSpecBuilder builder) {
            return SendThenDelegateProtocol.this.provideSubprotocolSpec(commonInput, sendFirstValue, builder);
        }

        @Override
        protected boolean provideAdditionalCheck(SendFirstValue sendFirstValue) {
            return SendThenDelegateProtocol.this.provideAdditionalCheck(commonInput, sendFirstValue);
        }
    }
}
