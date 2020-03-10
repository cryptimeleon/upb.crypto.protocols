package de.upb.crypto.clarc.protocols;

import de.upb.crypto.clarc.protocols.arguments.sigma.SigmaProtocol;
import de.upb.crypto.clarc.protocols.arguments.sigma.SigmaProtocolProverInstance;
import de.upb.crypto.clarc.protocols.arguments.sigma.SigmaProtocolVerifierInstance;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrInput;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrProtocol;
import de.upb.crypto.clarc.protocols.schnorr.stmts.DlogRepresentationStatement;
import de.upb.crypto.clarc.protocols.schnorr.stmts.set.SetMembershipPublicParameters;
import de.upb.crypto.clarc.protocols.schnorr.stmts.set.SetMembershipStatement;
import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.pairings.debug.DebugBilinearGroupProvider;
import de.upb.crypto.math.pairings.debug.DebugGroup;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zn;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class SchnorrTest {
    public static Group group = new DebugGroup("test", BigInteger.valueOf(13));
    public static BilinearGroup bilGroup = new DebugBilinearGroupProvider().provideBilinearGroup(80, BilinearGroup.Type.TYPE_3, 1);

    @Test
    public void testOriginalSchnorr() {
        GroupElement g = group.getUniformlyRandomElement();
        Zn.ZnElement x = group.getUniformlyRandomExponent();
        GroupElement h = g.pow(x);

        SchnorrProtocol protocol = new SchnorrProtocol(new DlogRepresentationStatement("originalSchnorr", g.expr().pow("x"), h.expr()));
        SchnorrInput commonInput = new SchnorrInput();
        SchnorrInput secretInput = new SchnorrInput();
        secretInput.put("x", x);

        runProtocol(protocol, commonInput, secretInput);
    }

    @Test
    public void testSetMembershipOnCommitment() {
        GroupElement g = bilGroup.getG1().getUniformlyRandomElement();
        GroupElement h = bilGroup.getG1().getUniformlyRandomElement();
        BigInteger x = BigInteger.valueOf(5);
        Zn.ZnElement r = g.getStructure().getUniformlyRandomExponent();
        GroupElement commitment = g.pow(x).op(h.pow(r));
        Set<BigInteger> set = Stream.iterate(BigInteger.ZERO, i -> i.add(BigInteger.ONE)).limit(10).collect(Collectors.toCollection(HashSet::new));
        SetMembershipPublicParameters pp = SetMembershipPublicParameters.generate(bilGroup, set);

        SchnorrProtocol protocol = new SchnorrProtocol(
                new DlogRepresentationStatement("openCommitment", g.expr().pow("x").opPow(h, "r"), commitment.expr()),
                new SetMembershipStatement("x below 10", pp, "x"));
        SchnorrInput commonInput = new SchnorrInput();
        SchnorrInput secretInput = new SchnorrInput();
        secretInput.put("x", x);
        secretInput.put("r", r);

        runProtocol(protocol, commonInput, secretInput);
    }

    protected void runProtocol(SigmaProtocol protocol, CommonInput commonInput, SecretInput secretInput) {
        SigmaProtocolProverInstance prover = protocol.getProverInstance(commonInput, secretInput);
        SigmaProtocolVerifierInstance verifier = protocol.getVerifierInstance(commonInput);

        Representation announcement = prover.nextMessage(null);
        System.out.println(announcement);
        Representation challenge = verifier.nextMessage(announcement);
        System.out.println(challenge);
        Representation response = prover.nextMessage(challenge);
        System.out.println(response);
        verifier.nextMessage(response);

        assert verifier.hasTerminated();
        assert verifier.getAcceptanceExpression().evaluate();
    }
}
