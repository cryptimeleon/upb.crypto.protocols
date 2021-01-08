package de.upb.crypto.clarc.protocols;

import de.upb.crypto.clarc.protocols.arguments.sigma.SigmaProtocol;
import de.upb.crypto.clarc.protocols.arguments.sigma.SigmaProtocolProverInstance;
import de.upb.crypto.clarc.protocols.arguments.sigma.SigmaProtocolVerifierInstance;
import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.pairings.debug.DebugBilinearGroupProvider;
import de.upb.crypto.math.pairings.debug.count.CountingBilinearGroup;
import de.upb.crypto.math.pairings.debug.count.CountingGroup;
import de.upb.crypto.math.serialization.Representation;

import java.math.BigInteger;

public class SchnorrTest {
    public static Group group = new CountingGroup("test", BigInteger.valueOf(13));
    //public static BilinearGroup bilGroup = new CountingBilinearGroup(BilinearGroup.Type.TYPE_3, )

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
