package de.upb.crypto.clarc.protocols.schnorr.stmts.api;

import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.clarc.protocols.arguments.sigma.AnnouncementSecret;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrInput;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrPreimage;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;

import java.math.BigInteger;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

public abstract class SendThenDelegateStatement extends SchnorrStatement {
    public SendThenDelegateStatement(String name) {
        super(name);
    }

    protected abstract List<SchnorrStatement> getStatements(SchnorrInput commonInput, Announcement sendValue);
    protected getAdditionalWitnesses()
    protected abstract Announcement getSendValue(SchnorrInput commonInput, SchnorrInput secretInput);
    protected abstract Announcement simulateSendValue(SchnorrInput commonInput);

    @Override
    public Collection<SchnorrVariable> getWitnesses(SchnorrInput commonInput) {
        HashSet<SchnorrVariable> vars = new HashSet<>();

        return vars;
    }

    @Override
    public SchnorrVariableValue getInternalWitnessValue(SchnorrInput commonInput, SchnorrInput secretInput, Announcement internalAnnouncement, AnnouncementSecret announcementSecret, SchnorrVariable variable) {
        return null;
    }

    @Override
    public AnnouncementSecret generateInternalAnnouncementSecret(SchnorrInput commonInput, SchnorrInput secretInput) {
        return null;
    }

    @Override
    public Announcement generateInternalAnnouncement(SchnorrInput commonInput, SchnorrInput secretInput, AnnouncementSecret announcementSecret) {
        return null;
    }

    @Override
    public Announcement recreateInternalAnnouncement(SchnorrInput commonInput, Representation repr) {
        return null;
    }

    @Override
    public Announcement simulateInternalAnnouncement(SchnorrInput commonInput) {
        return null;
    }

    @Override
    public GroupElement recreateImage(SchnorrInput commonInput, Representation repr) {
        return null;
    }

    @Override
    public GroupElement getHomomorphismTarget(SchnorrInput commonInput, Announcement internalAnnouncement) {
        return null;
    }

    @Override
    public GroupElement evaluateHomomorphism(SchnorrInput commonInput, Announcement internalAnnouncement, SchnorrPreimage preimage) {
        return null;
    }

    @Override
    public BigInteger getChallengeSpaceSize(SchnorrInput commonInput) {
        return null;
    }
}
