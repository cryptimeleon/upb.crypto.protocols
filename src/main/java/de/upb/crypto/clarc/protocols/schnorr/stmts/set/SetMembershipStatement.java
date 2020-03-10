package de.upb.crypto.clarc.protocols.schnorr.stmts.set;

import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.clarc.protocols.arguments.sigma.AnnouncementSecret;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrImage;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrInput;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrPreimage;
import de.upb.crypto.clarc.protocols.schnorr.expr.InternalExponentVariableExpr;
import de.upb.crypto.clarc.protocols.schnorr.expr.InternalGroupVariableExpr;
import de.upb.crypto.clarc.protocols.schnorr.stmts.api.*;
import de.upb.crypto.math.expressions.group.GroupElementExpression;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zn;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collection;

public class SetMembershipStatement extends SchnorrStatement {
    protected SetMembershipPublicParameters pp;
    SchnorrZnVariable member;
    SchnorrZnVariable r;
    SchnorrGroupElemVariable blindedSignature;
    GroupElementExpression homomorphicPart;
    GroupElementExpression homomorphismTarget;

    public SetMembershipStatement(String name, SetMembershipPublicParameters pp, String memberName) {
        super(name);
        this.pp = pp;
        this.member = new SchnorrZnVariable(memberName, pp.getZn());
        this.r = new SchnorrZnVariable("r", pp.getZn(), this);
        this.blindedSignature = new SchnorrGroupElemVariable("blindedSignature", pp.g1.getStructure());
        homomorphicPart = pp.bilinearGroup.getBilinearMap().expr(
                    new InternalGroupVariableExpr(blindedSignature),
                    pp.g2.expr().pow(member.getName())
                ).op(pp.bilinearGroup.getBilinearMap().expr(pp.g1, pp.g2).pow(new InternalExponentVariableExpr(r).negate()));
        homomorphismTarget = pp.bilinearGroup.getBilinearMap().expr(
                new InternalGroupVariableExpr(blindedSignature),
                pp.pk.expr()
        ).inv();
    }

    @Override
    public Collection<SchnorrVariable> getWitnesses(SchnorrInput commonInput) {
        return Arrays.asList(member, r);
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
        return new SetMembershipAnnouncement(getSignatureOnMember(secretInput).pow(((SetMembershipAnnouncementSecret) announcementSecret).r));
    }

    private GroupElement getSignatureOnMember(SchnorrInput secretInput) {
        return pp.signatures.get(secretInput.getInteger(member.getName()));
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
    public SchnorrImage recreateImage(SchnorrInput commonInput, Representation repr) {
        return new GroupElementImage(repr, pp.bilinearGroup.getGT());
    }

    @Override
    public SchnorrImage getHomomorphismTarget(SchnorrInput commonInput, Announcement internalAnnouncement) {
        return new GroupElementImage(substituteBlindedSignature(homomorphismTarget, internalAnnouncement));
    }

    @Override
    public SchnorrImage evaluateHomomorphism(SchnorrInput commonInput, Announcement internalAnnouncement, SchnorrPreimage preimage) {
        return new GroupElementImage(substituteBlindedSignature(homomorphicPart, internalAnnouncement).substitute(preimage));
    }

    protected GroupElementExpression substituteBlindedSignature(GroupElementExpression e, Announcement internalAnnouncement) {
        return e.substitute(expr -> expr instanceof InternalGroupVariableExpr && ((InternalGroupVariableExpr) expr).getVariable().equals(blindedSignature) ? ((SetMembershipAnnouncement) internalAnnouncement).blindedSig.expr() : null);
    }

    @Override
    public BigInteger getChallengeSpaceSize(SchnorrInput commonInput) {
        return pp.getZn().size();
    }

    protected class SetMembershipAnnouncementSecret implements AnnouncementSecret {
        public final Zn.ZnElement r;

        public SetMembershipAnnouncementSecret(Zn.ZnElement r) {
            this.r = r;
        }
    }

    protected class SetMembershipAnnouncement implements Announcement {
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
