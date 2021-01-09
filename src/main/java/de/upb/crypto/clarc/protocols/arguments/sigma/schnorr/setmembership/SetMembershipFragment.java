package de.upb.crypto.clarc.protocols.arguments.sigma.schnorr.setmembership;

import de.upb.crypto.clarc.protocols.arguments.sigma.schnorr.LinearStatementFragment;
import de.upb.crypto.clarc.protocols.arguments.sigma.schnorr.variables.SchnorrVariableAssignment;
import de.upb.crypto.clarc.protocols.arguments.sigma.schnorr.variables.SchnorrZnVariable;
import de.upb.crypto.clarc.protocols.arguments.sigma.schnorr.SendThenDelegateFragment;
import de.upb.crypto.math.expressions.exponent.ExponentExpr;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zn;

public class SetMembershipFragment extends SendThenDelegateFragment {
    private final SetMembershipPublicParameters pp;
    private final ExponentExpr member;

    public SetMembershipFragment(SetMembershipPublicParameters pp, ExponentExpr member) {
        this.pp = pp;
        this.member = member;
    }

    @Override
    protected ProverSpec provideProverSpec(SchnorrVariableAssignment outerWitnesses, ProverSpecBuilder builder) {
        Zn.ZnElement r = pp.getZn().getUniformlyRandomNonzeroElement();
        builder.putWitnessValue("r", r);

        //Compute member with respect to given witnesses
        Zn.ZnElement memberVal = member.evaluate(pp.getZn(), outerWitnesses);

        //Pick the right signature for memberVal
        GroupElement signature = pp.signatures.get(memberVal.getInteger());

        //Blind signature with blinding value
        GroupElement blindedSignature = signature.pow(r);
        builder.setSendFirstValue(new AlgebraicSendFirstValue(blindedSignature));

        return builder.build();
    }

    @Override
    protected SendFirstValue recreateSendFirstValue(Representation repr) {
        return new AlgebraicSendFirstValue(repr, pp.bilinearGroup.getG1());
    }

    @Override
    protected SendFirstValue simulateSendFirstValue() {
        return new AlgebraicSendFirstValue(pp.bilinearGroup.getG1().getUniformlyRandomNonNeutral());
    }

    @Override
    protected SubprotocolSpec provideSubprotocolSpec(SendFirstValue sendFirstValue, SubprotocolSpecBuilder builder) {
        GroupElement blindedSignature = ((AlgebraicSendFirstValue) sendFirstValue).getGroupElement(0);

        //Add proof that prover knows how to derandomize the blinded signature such that it's valid on member.
        SchnorrZnVariable signatureBlindingValue = builder.addZnVariable("r", pp.getZn()); //"prove knowledge of r"
        builder.addSubprotocol("signatureCheck", //"prove the following equation about r and the member"
            new LinearStatementFragment( //e(blindedSignature, pk * g2^member) = e(g1,g2)^r, where blindedSignature = g1^(r * 1/(sk + member)) and pk = g2^sk.
                    pp.bilinearGroup.getBilinearMap().applyExpr(blindedSignature, pp.pk.op(pp.g2.pow(member)))
                    .isEqualTo(pp.egg.pow(signatureBlindingValue))
            )
        );

        return builder.build();
    }

    @Override
    protected boolean provideAdditionalCheck(SendFirstValue sendFirstValue) {
        return !((AlgebraicSendFirstValue) sendFirstValue).getGroupElement(0).isNeutralElement();
    }
}
