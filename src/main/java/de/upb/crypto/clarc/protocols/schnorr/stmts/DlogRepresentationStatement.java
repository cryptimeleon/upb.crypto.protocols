package de.upb.crypto.clarc.protocols.schnorr.stmts;

import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.clarc.protocols.arguments.sigma.AnnouncementSecret;
import de.upb.crypto.clarc.protocols.arguments.sigma.EmptyAnnouncement;
import de.upb.crypto.clarc.protocols.arguments.sigma.EmptyAnnouncementSecret;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrImage;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrInput;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrPreimage;
import de.upb.crypto.clarc.protocols.schnorr.stmts.api.*;
import de.upb.crypto.math.expressions.exponent.ExponentVariableExpr;
import de.upb.crypto.math.expressions.group.GroupElementExpression;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.serialization.Representation;

import java.math.BigInteger;
import java.util.*;

public class DlogRepresentationStatement extends SchnorrStatement {
    Group group;
    GroupElementExpression homomorphicPart, constantPart;

    public DlogRepresentationStatement(String name, GroupElementExpression homomorphicPart, GroupElementExpression constantPart) {
        super(name);
        this.group = constantPart.getGroup();
        if (this.group == null)
            this.group = homomorphicPart.getGroup();
        if (this.group.size() == null || !this.group.size().isProbablePrime(20))
            throw new IllegalArgumentException("Need prime order group.");
        this.homomorphicPart = homomorphicPart;
        this.constantPart = constantPart;
    }

    @Override
    public ArrayList<SchnorrVariable> getWitnesses(SchnorrInput commonInput) {
        ArrayList<SchnorrVariable> variables = new ArrayList<>();
        getEffectiveHomomorphicPart(commonInput).getVariables().forEach(v -> {
            if (v instanceof ExponentVariableExpr)
                variables.add(new SchnorrZnVariable(v.getName(), group.getZn()));
        });

        return variables;
    }

    @Override
    public SchnorrVariableValue getInternalWitnessValue(SchnorrInput commonInput, SchnorrInput secretInput, Announcement internalAnnouncement, AnnouncementSecret announcementSecret, SchnorrVariable variable) {
        throw new IllegalArgumentException("DlogRepresentationStatement does not have any internal witnesses"); //this call should never happen.
    }

    @Override
    public AnnouncementSecret generateInternalAnnouncementSecret(SchnorrInput commonInput, SchnorrInput secretInput) {
        return new EmptyAnnouncementSecret();
    }

    @Override
    public Announcement generateInternalAnnouncement(SchnorrInput commonInput, SchnorrInput secretInput, AnnouncementSecret announcementSecret) {
        return new EmptyAnnouncement();
    }

    @Override
    public Announcement recreateInternalAnnouncement(SchnorrInput commonInput, Representation repr) {
        return new EmptyAnnouncement();
    }

    @Override
    public Announcement simulateAnnouncement(SchnorrInput commonInput) {
        return new EmptyAnnouncement();
    }

    @Override
    public SchnorrImage recreateImage(SchnorrInput commonInput, Representation repr) {
        return new GroupElementImage(repr, group);
    }

    @Override
    public SchnorrImage getHomomorphismTarget(SchnorrInput commonInput, Announcement internalAnnouncement) {
        return new GroupElementImage(constantPart.substitute(commonInput));
    }

    @Override
    public SchnorrImage evaluateHomomorphism(SchnorrInput commonInput, Announcement internalAnnouncement, SchnorrPreimage preimage) {
        return new GroupElementImage(getEffectiveHomomorphicPart(commonInput).substitute(preimage));
    }

    @Override
    public BigInteger getChallengeSpaceSize(SchnorrInput commonInput) {
        return group.size();
    }

    protected GroupElementExpression getEffectiveHomomorphicPart(SchnorrInput commonInput) {
        return homomorphicPart.substitute(commonInput);
    }
}
