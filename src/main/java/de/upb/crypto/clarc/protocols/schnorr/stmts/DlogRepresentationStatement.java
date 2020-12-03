package de.upb.crypto.clarc.protocols.schnorr.stmts;

import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.clarc.protocols.arguments.sigma.AnnouncementSecret;
import de.upb.crypto.clarc.protocols.arguments.sigma.EmptyAnnouncement;
import de.upb.crypto.clarc.protocols.arguments.sigma.EmptyAnnouncementSecret;

import de.upb.crypto.clarc.protocols.schnorr.SchnorrInput;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrPreimage;
import de.upb.crypto.clarc.protocols.schnorr.stmts.api.*;
import de.upb.crypto.math.expressions.exponent.ExponentVariableExpr;
import de.upb.crypto.math.expressions.group.GroupElementConstantExpr;
import de.upb.crypto.math.expressions.group.GroupElementExpression;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
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
        if (this.group.size() == null)
            throw new IllegalArgumentException("Need finite known order group.");
        this.homomorphicPart = homomorphicPart;
        this.constantPart = constantPart;
    }

    public DlogRepresentationStatement(String name, GroupElementExpression homomorphicPart) {
        this(name, homomorphicPart, new GroupElementConstantExpr(homomorphicPart.getGroup().getNeutralElement()));
    }

    @Override
    public ArrayList<SchnorrVariable> getWitnesses(SchnorrInput commonInput) {
        ArrayList<SchnorrVariable> variables = new ArrayList<>();
        getEffectiveHomomorphicPart(commonInput).getVariables().forEach(v -> {
            if (v instanceof ExponentVariableExpr)
                variables.add(new SchnorrZnVariable(v, group.getZn()));
        });

        return variables;
    }

    @Override
    public SchnorrVariableValue getInternalWitnessValue(SchnorrInput commonInput, SchnorrInput secretInput, Announcement internalAnnouncement, AnnouncementSecret announcementSecret, SchnorrVariable variable) {
        throw new IllegalArgumentException("This does not have any internal witnesses"); //this call should never happen.
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
    public Announcement simulateInternalAnnouncement(SchnorrInput commonInput) {
        return new EmptyAnnouncement();
    }

    @Override
    public GroupElement recreateImage(SchnorrInput commonInput, Representation repr) {
        return group.getElement(repr);
    }

    @Override
    public GroupElement getHomomorphismTarget(SchnorrInput commonInput, Announcement internalAnnouncement) {
        return getEffectiveConstantPart(commonInput);
    }

    @Override
    public GroupElement evaluateHomomorphism(SchnorrInput commonInput, Announcement internalAnnouncement, SchnorrPreimage preimage) {
        return getEffectiveHomomorphicPart(commonInput).evaluate(preimage);
    }

    @Override
    public BigInteger getChallengeSpaceSize(SchnorrInput commonInput) {
        return group.size();
    }

    protected GroupElementExpression getEffectiveHomomorphicPart(SchnorrInput commonInput) {
        return homomorphicPart.substitute(commonInput);
    }

    protected GroupElement getEffectiveConstantPart(SchnorrInput commonInput) {
        return constantPart.evaluate(commonInput);
    }
}
