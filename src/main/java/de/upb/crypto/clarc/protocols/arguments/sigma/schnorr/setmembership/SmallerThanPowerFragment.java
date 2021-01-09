package de.upb.crypto.clarc.protocols.arguments.sigma.schnorr.setmembership;

import de.upb.crypto.clarc.protocols.arguments.sigma.schnorr.DelegateFragment;
import de.upb.crypto.clarc.protocols.arguments.sigma.schnorr.LinearExponentStatementFragment;
import de.upb.crypto.clarc.protocols.arguments.sigma.schnorr.variables.SchnorrVariableAssignment;
import de.upb.crypto.clarc.protocols.arguments.sigma.schnorr.variables.SchnorrZnVariable;
import de.upb.crypto.math.expressions.exponent.ExponentEmptyExpr;
import de.upb.crypto.math.expressions.exponent.ExponentExpr;
import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.structures.integers.IntegerRing;
import de.upb.crypto.math.structures.zn.Zn;

import java.math.BigInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class SmallerThanPowerFragment extends DelegateFragment {
    protected final int base;
    protected final int power;
    protected final ExponentExpr member;
    protected final SetMembershipPublicParameters pp;

    public SmallerThanPowerFragment(ExponentExpr member, int base, int power, SetMembershipPublicParameters pp) {
        this.base = base;
        this.power = power;
        this.member = member;
        this.pp = pp;

        if (pp.signatures.size() != base || IntStream.range(0, base).anyMatch(i -> !pp.signatures.containsKey(BigInteger.valueOf(i))))
            throw new IllegalArgumentException("Unfit SetMembershiptPublicParameters");
    }

    public static SetMembershipPublicParameters generatePublicParameters(BilinearGroup group, int base) {
        return SetMembershipPublicParameters.generate(group, IntStream.range(0, base).mapToObj(BigInteger::valueOf).collect(Collectors.toSet()));
    }

    @Override
    protected ProverSpec provideProverSpecWithNoSendFirst(SchnorrVariableAssignment outerWitnesses, ProverSpecBuilder builder) {
        Zn.ZnElement memberVal = this.member.evaluate(pp.getZn(), outerWitnesses);

        //Decompose memberVal into digits
        BigInteger[] digits = IntegerRing.decomposeIntoDigits(memberVal.getInteger(), BigInteger.valueOf(base), power);

        //Add digits to witnesses
        for (int i=0; i<power; i++)
            builder.putWitnessValue("digit"+i, pp.getZn().valueOf(digits[i]));

        return builder.build();
    }

    @Override
    protected SubprotocolSpec provideSubprotocolSpec(SubprotocolSpecBuilder builder) {
        //Need to prove knowledge of digits
        SchnorrZnVariable[] digits = new SchnorrZnVariable[power];
        for (int i=0; i<power; i++)
            digits[i] = builder.addZnVariable("digit"+i, pp.getZn());

        //... such that those digits represent member
        Zn.ZnElement base = pp.getZn().valueOf(this.base);
        ExponentExpr weightedSum = new ExponentEmptyExpr();
        for (int i=0; i<power; i++)
            weightedSum = weightedSum.add(digits[i].mul(base.pow(i)));
        builder.addSubprotocol("digitSum", new LinearExponentStatementFragment(weightedSum.isEqualTo(member), pp.getZn()));

        //... and each digit is in the set {0,...,base-1} of valid digits
        for (int i=0; i<power; i++)
            builder.addSubprotocol("digit"+i+"valid", new SetMembershipFragment(pp, digits[i]));

        return builder.build();
    }
}
