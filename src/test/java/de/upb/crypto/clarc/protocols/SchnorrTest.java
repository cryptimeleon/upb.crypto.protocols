package de.upb.crypto.clarc.protocols;

import de.upb.crypto.clarc.protocols.arguments.sigma.SigmaProtocolProverInstance;
import de.upb.crypto.clarc.protocols.arguments.sigma.SigmaProtocolVerifierInstance;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrInput;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrProtocol;
import de.upb.crypto.clarc.protocols.schnorr.stmts.DlogRepresentationStatement;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.pairings.debug.DebugGroup;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zn;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

public class SchnorrTest {
    public static Group group = new DebugGroup("test", BigInteger.valueOf(13));

    @Test
    public void testOriginalSchnorr() {
        GroupElement g = group.getUniformlyRandomElement();
        Zn.ZnElement x = group.getUniformlyRandomExponent();
        GroupElement h = g.pow(x);

        SchnorrProtocol protocol = new SchnorrProtocol(new DlogRepresentationStatement("originalSchnorr", g.expr().pow("x"), h.expr()));
        SchnorrInput commonInput = new SchnorrInput();
        SchnorrInput secretInput = new SchnorrInput();
        secretInput.put("x", x);
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
