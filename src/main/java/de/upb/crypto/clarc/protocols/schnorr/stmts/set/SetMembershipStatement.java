package de.upb.crypto.clarc.protocols.schnorr.stmts.set;

import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.clarc.protocols.arguments.sigma.AnnouncementSecret;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrInput;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrPreimage;
import de.upb.crypto.clarc.protocols.schnorr.stmts.api.*;
import de.upb.crypto.clarc.protocols.schnorr.stmts.api.expr.InternalZnVariableExpr;
import de.upb.crypto.math.expressions.VariableExpression;
import de.upb.crypto.math.expressions.exponent.ExponentExpr;
import de.upb.crypto.math.expressions.exponent.ExponentVariableExpr;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zn;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Objects;

public class SetMembershipStatement extends SchnorrStatement {
    protected SetMembershipPublicParameters pp;
    protected ExponentExpr member;
    protected SchnorrZnVariable r;

    /**
     *
     * @param name
     * @param pp
     * @param member the value that's supposed to be in the set. Must be an expression that's linear in the larger protocol's witnesses
     */
    public SetMembershipStatement(String name, SetMembershipPublicParameters pp, ExponentExpr member) {
        super(name);
        this.pp = pp;
        this.member = member;

        this.r = new SchnorrZnVariable(new InternalZnVariableExpr(name, "r"), pp.getZn());
    }

    @Override
    public Collection<SchnorrVariable> getWitnesses(SchnorrInput commonInput) {
        ArrayList<SchnorrVariable> vars = new ArrayList<>();
        member.getVariables().forEach(v -> vars.add(new SchnorrZnVariable(v, pp.getZn())));
        vars.add(r);
        return vars;
    }

    @Override
    public SchnorrVariableValue getInternalWitnessValue(SchnorrInput commonInput, SchnorrInput secretInput, Announcement internalAnnouncement, AnnouncementSecret announcementSecret, SchnorrVariable variable) {
        return new SchnorrZnVariableValue(((SetMembershipAnnouncementSecret) announcementSecret).r, r);
    }

    @Override
    public AnnouncementSecret generateInternalAnnouncementSecret(SchnorrInput commonInput, SchnorrInput secretInput) {
        return new SetMembershipAnnouncementSecret(pp.getZn().getUniformlyRandomUnit());
    }

    @Override
    public Announcement generateInternalAnnouncement(SchnorrInput commonInput, SchnorrInput secretInput, AnnouncementSecret announcementSecret) {
        return new SetMembershipAnnouncement(getSignatureOnMember(commonInput, secretInput).pow(((SetMembershipAnnouncementSecret) announcementSecret).r));
    }

    private GroupElement getSignatureOnMember(SchnorrInput commonInput, SchnorrInput secretInput) {
        return pp.signatures.get(member.substitute(commonInput).evaluate(pp.getZn(), secretInput).getInteger());
    }

    @Override
    public Announcement recreateInternalAnnouncement(SchnorrInput commonInput, Representation repr) {
        return new SetMembershipAnnouncement(pp.g1.getStructure().getElement(repr));
    }

    @Override
    public Announcement simulateInternalAnnouncement(SchnorrInput commonInput) {
        return new SetMembershipAnnouncement(pp.g1.getStructure().getUniformlyRandomNonNeutral());
    }

    @Override
    public GroupElement recreateImage(SchnorrInput commonInput, Representation repr) {
        return pp.bilinearGroup.getGT().getElement(repr);
    }

    @Override
    public GroupElement getHomomorphismTarget(SchnorrInput commonInput, Announcement internalAnnouncement) {
        return pp.bilinearGroup.getBilinearMap().apply(
                ((SetMembershipAnnouncement) internalAnnouncement).blindedSig,
                pp.pk
        ).inv();
    }

    @Override
    public GroupElement evaluateHomomorphism(SchnorrInput commonInput, Announcement internalAnnouncement, SchnorrPreimage preimage) {
        return pp.bilinearGroup.getBilinearMap().apply(
                    ((SetMembershipAnnouncement) internalAnnouncement).blindedSig,
                    pp.g2.pow(member.evaluate(pp.getZn(), preimage))
        ).op(
                pp.bilinearGroup.getBilinearMap().apply(pp.g1, pp.g2).pow(r.getVariableExpr().negate().evaluate(pp.getZn(), preimage))
        );
    }

    @Override
    public BigInteger getChallengeSpaceSize(SchnorrInput commonInput) {
        return pp.getZn().size();
    }

    protected static class SetMembershipAnnouncementSecret implements AnnouncementSecret {
        public final Zn.ZnElement r;

        public SetMembershipAnnouncementSecret(Zn.ZnElement r) {
            this.r = r;
        }
    }

    protected static class SetMembershipAnnouncement implements Announcement {
        public final GroupElement blindedSig;

        public SetMembershipAnnouncement(GroupElement blindedSig) {
            this.blindedSig = blindedSig;
        }

        @Override
        public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
            return blindedSig.updateAccumulator(accumulator);
        }

        @Override
        public Representation getRepresentation() {
            return blindedSig.getRepresentation();
        }
    }
}
