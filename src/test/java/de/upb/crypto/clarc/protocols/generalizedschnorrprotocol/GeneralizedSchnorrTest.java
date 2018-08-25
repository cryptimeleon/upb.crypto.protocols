package de.upb.crypto.clarc.protocols.generalizedschnorrprotocol;

import de.upb.crypto.clarc.protocols.InteractiveThreeWayAoKTester;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class GeneralizedSchnorrTest {

    private BigInteger small_prime;
    private int lamda = 260;
    private int n = 3;
    private int m = 2;
    private Zp zp;
    private Group[] groups;
    private GeneralizedSchnorrProtocol protocolProver;
    // different prover-protocol for negative test cases
    private GeneralizedSchnorrProtocol secondProtocolProver;
    private GeneralizedSchnorrProtocol protocolVerifier;


    @BeforeAll
    public void setUp() {
        GenSchnorrTestdataProvider provider = new GenSchnorrTestdataProvider();
        groups = provider.generateGenSchnorrGroups();
        zp = provider.generateGenSchnorrZPGroup(groups[0]);
        protocolProver = provider.getGenSchorrProtocol(m, n, groups);
        do {
            secondProtocolProver = provider.getGenSchorrProtocol(m, n, groups);
        } while (protocolProver.equals(secondProtocolProver));
        protocolVerifier = new GeneralizedSchnorrProtocol(protocolProver.getProblems(),
                null, (GeneralizedSchnorrPublicParameter) protocolProver.getPublicParameters());
    }

    /**
     * Positive test checking that for a correct protocol execution the verifier accepts.
     * The test is checking the protocol execution with internal randomness.
     */
    @Test
    public void testGenSchnorrInternalRandomness() {
        InteractiveThreeWayAoKTester.protocolExecutionInternalRandomnessTest(protocolProver, protocolVerifier);
        assertArrayEquals(protocolVerifier.getProblems(), protocolProver.getProblems(),
                "The problems of the Generalized Schnorr protocols with internal randomness are inequal!");
    }

    /**
     * This negative test checks cases where the verify method is called with not matching parameters and therefore
     * should return false for internal randomness.
     */
    @Test
    public void testNeqGenSchnorrInternalRandomness() {
        InteractiveThreeWayAoKTester.protocolExecutionInternalRandomnessNegativeTest(protocolProver,
                secondProtocolProver, protocolVerifier);
        assertArrayEquals(protocolVerifier.getProblems(), protocolProver.getProblems(),
                "The problems of the Generalized Schnorr protocols with internal randomness are inequal!");
    }

    @Test
    public void recreateTest() {
        InteractiveThreeWayAoKTester.recreateTest(protocolProver, protocolVerifier);
    }
}
