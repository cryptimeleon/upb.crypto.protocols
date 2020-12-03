package de.upb.crypto.clarc.protocols.schnorr.stmts.set;

import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.clarc.protocols.arguments.sigma.AnnouncementSecret;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrInput;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrPreimage;
import de.upb.crypto.clarc.protocols.schnorr.stmts.api.*;
import de.upb.crypto.math.expressions.exponent.ExponentConstantExpr;
import de.upb.crypto.math.expressions.exponent.ExponentExpr;
import de.upb.crypto.math.expressions.exponent.ExponentVariableExpr;
import de.upb.crypto.math.expressions.group.GroupElementExpression;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.integers.IntegerRing;
import de.upb.crypto.math.structures.zn.Zn;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

public class LessThanBasePowerStatement extends SchnorrStatement {
    protected SetMembershipPublicParameters pp;
    protected int base;
    protected int power;
    protected ExponentExpr smallValue;

    protected SchnorrZnVariable[] blindingValue;
    protected SchnorrGroupElemVariable[] blindedSignature;
    protected SchnorrZnVariable[] digits;
    protected GroupElementExpression[] homomorphicPart;
    protected GroupElementExpression[] homomorphismTarget;
    protected ExponentExpr homomorphicPartSumStatement;
    protected ExponentExpr homomorphismTargetSumStatement;

    /**
     * Construct a proof that smallVariable lies within the interval [0, base^power-1] (beware of mod p overflow).
     */
    public LessThanBasePowerStatement(String name, int base, int power, ExponentExpr smallValue, SetMembershipPublicParameters pp) {
        super(name);
        this.pp = pp;
        this.base = base;
        this.power = power;
        this.smallValue = smallValue;

        if (pp.signatures.keySet().size() != base)
            throw new IllegalArgumentException("pp don't fit");
        for (int i=0; i<base;i++)
            if (!pp.signatures.containsKey(BigInteger.valueOf(i)))
                throw new IllegalArgumentException("pp don't fit");

        //Prepare statement
        blindingValue = new SchnorrZnVariable[power];
        blindedSignature = new SchnorrGroupElemVariable[power]; //will be sigma_i (where sigma_i is a signature on the ith digit of smallVariable-shift raised to power of r_i).
        homomorphicPart = new GroupElementExpression[power]; //will be e(sigma_i, g2^digits_i) * e(g1, g2)^-r_i, which should equal e(sigma_i, pk)^-1
        homomorphismTarget = new GroupElementExpression[power]; //e(sigma_i, pk)^-1 as mentioned in the line above this one
        homomorphicPartSumStatement = new ExponentVariableExpr(smallVariable).negate(); //will be -smallVariable + \sum digit_i * base^i (this should be -shift)
        homomorphismTargetSumStatement = new ExponentVariableExpr(shift).negate(); //shift that the above should sum up to
        for (int i=0; i<power; i++) { //for each allowed digit of smallVariable
            blindingValue[i] = new SchnorrZnVariable("r"+i, pp.getZn(), this);
            blindedSignature[i] = new SchnorrGroupElemVariable("sigma"+i, pp.g1.getStructure(), this);
            digits[i] = new SchnorrZnVariable("digit"+i, pp.getZn(), this);

            homomorphicPart[i] = pp.bilinearGroup.getBilinearMap().expr(
                    new InternalSchnorrGroupVariableExpr(blindedSignature[i]),
                    pp.g2.expr().pow(new InternalSchnorrExponentVariableExpr(digits[i])) //TODO check that this pow() is moved to G1.
                ).op(pp.bilinearGroup.getBilinearMap().expr(pp.g1, pp.g2).pow(new InternalSchnorrExponentVariableExpr(blindingValue[i]).negate()));
            homomorphismTarget[i] = pp.bilinearGroup.getBilinearMap().expr(
                    new InternalSchnorrGroupVariableExpr(blindedSignature[i]),
                    pp.pk.expr()
                ).inv(); //TODO check that this inv() is automatically moved into G1 when evaluating. Alternatively, move it yourself.

            homomorphicPartSumStatement = homomorphicPartSumStatement.add(new InternalSchnorrExponentVariableExpr(digits[i]).mul(new ExponentConstantExpr(base).pow(i)));
        }
    }

    @Override
    public Collection<SchnorrVariable> getWitnesses(SchnorrInput commonInput) {
        ArrayList<SchnorrVariable> variables = new ArrayList<>();

        variables.add(smallVariable); //external
        variables.addAll(Arrays.asList(blindingValue)); //internal
        variables.addAll(Arrays.asList(digits)); //internal

        return variables;
    }

    @Override
    public SchnorrVariableValue getInternalWitnessValue(SchnorrInput commonInput, SchnorrInput secretInput, Announcement internalAnnouncement, AnnouncementSecret announcementSecret, SchnorrVariable variable) {
        if (variable.getVariableExpr().startsWith("r")) {
            int i = Integer.parseInt(variable.getVariableExpr().substring(1));
            return new SchnorrZnVariableValue(((LessThanBasePowerSecret) announcementSecret).blindingValues[i], (SchnorrZnVariable) variable);
        }

        if (variable.getVariableExpr().startsWith("digit")) {
            int i = Integer.parseInt(variable.getVariableExpr().substring(5));
            return new SchnorrZnVariableValue(pp.getZn().valueOf(((LessThanBasePowerSecret) announcementSecret).digits[i]), (SchnorrZnVariable) variable);
        }

        throw new IllegalArgumentException("This shouldn't happen");
    }

    @Override
    public AnnouncementSecret generateInternalAnnouncementSecret(SchnorrInput commonInput, SchnorrInput secretInput) {
        BigInteger[] digits = IntegerRing.decomposeIntoDigits(secretInput.getInteger(smallVariable.getVariableExpr()).subtract(commonInput.getInteger(shift)), BigInteger.valueOf(base), power);
        Zn.ZnElement[] blindingSecrets = new Zn.ZnElement[power];
        for (int i=0;i<power;i++)
            blindingSecrets[i] = pp.getZn().getUniformlyRandomUnit(); //TODO check that getZn() is cached. Don't create new objects each time.
        return new LessThanBasePowerSecret(blindingSecrets, digits);
    }

    @Override
    public Announcement generateInternalAnnouncement(SchnorrInput commonInput, SchnorrInput secretInput, AnnouncementSecret announcementSecret) {
        //Generate blinded signatures
        LessThanBasePowerSecret secret = (LessThanBasePowerSecret) announcementSecret;
        ArrayList<FutureGroupElement> blindedSigFutures = new ArrayList<>(power);

        for (int i=0;i<power;i++)
            blindedSigFutures.add(pp.signatures.get(secret.digits[i]).expr().pow(secret.blindingValues[i]).evaluateAsync());

        ArrayList<GroupElement> blindedSigs = new ArrayList<>(power);
        for (int i=0;i<power;i++)
            blindedSigs.add(blindedSigFutures.get(i).get());

        return new LessThanBasePowerAnnouncement(blindedSigs);
    }

    @Override
    public Announcement recreateInternalAnnouncement(SchnorrInput commonInput, Representation repr) {
        return new LessThanBasePowerAnnouncement(repr);
    }

    @Override
    public Announcement simulateInternalAnnouncement(SchnorrInput commonInput) {
        ArrayList<GroupElement> simulatedSigs = new ArrayList<>();
        for (int i=0;i<power;i++)
            simulatedSigs.add(pp.bilinearGroup.getG1().getUniformlyRandomNonNeutral()); //TODO this could also be parallelized with some sort of future random group element or rnd group elem expr
        return new LessThanBasePowerAnnouncement(simulatedSigs);
    }

    @Override
    public GroupElement recreateImage(SchnorrInput commonInput, Representation repr) {
        return new GroupElementImage(repr, );
    }

    @Override
    public GroupElement getHomomorphismTarget(SchnorrInput commonInput, Announcement internalAnnouncement) {
        return new GroupElementImage(substituteBlindedSignatures(homomorphismTarget, internalAnnouncement));
    }

    @Override
    public GroupElement evaluateHomomorphism(SchnorrInput commonInput, Announcement internalAnnouncement, SchnorrPreimage preimage) {
        return new GroupElementImage(substituteBlindedSignatures(homomorphicPart, internalAnnouncement).substitute(preimage));
    }

    protected GroupElementExpression[] substituteBlindedSignatures(GroupElementExpression[] e, Announcement internalAnnouncement) {
        GroupElementExpression[] result = new GroupElementExpression[e.length];
        for (int i=0;i<e.length;i++) {
            int j = i;
            result[i] = e[i].substitute(expr -> expr instanceof InternalSchnorrGroupVariableExpr && ((InternalSchnorrGroupVariableExpr) expr).getVariable().equals(blindedSignature[j]) ? ((LessThanBasePowerAnnouncement) internalAnnouncement).blindedSig.get(j).expr() : null);
        }
        return result;
    }

    @Override
    public BigInteger getChallengeSpaceSize(SchnorrInput commonInput) {
        return pp.getZn().size();
    }

    protected class LessThanBasePowerSecret implements AnnouncementSecret {
        public final Zn.ZnElement[] blindingValues;
        public final BigInteger[] digits;

        public LessThanBasePowerSecret(Zn.ZnElement[] blindingValues, BigInteger[] digits) {
            this.blindingValues = blindingValues;
            this.digits = digits;
        }
    }

    protected class LessThanBasePowerAnnouncement implements Announcement {
        @UniqueByteRepresented
        public final List<GroupElement> blindedSig;

        public LessThanBasePowerAnnouncement(ArrayList<GroupElement> blindedSig) {
            this.blindedSig = blindedSig;
        }

        public LessThanBasePowerAnnouncement(Representation repr) {
            blindedSig = new ArrayList<>(power);
            for (Representation sigRepr : repr.list())
                blindedSig.add(pp.bilinearGroup.getG1().getElement(sigRepr));
        }

        @Override
        public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
            return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
        }

        @Override
        public Representation getRepresentation() {
            ListRepresentation repr = new ListRepresentation();
            blindedSig.forEach(s -> repr.put(s.getRepresentation()));
            return repr;
        }
    }
}
