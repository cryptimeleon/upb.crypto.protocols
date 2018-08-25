package de.upb.crypto.clarc.protocols.damgardtechnique;

import de.upb.crypto.clarc.protocols.InteractiveThreeWayAoKTester;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GenSchnorrTestdataProvider;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProblem;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrPublicParameter;
import de.upb.crypto.craco.commitment.HashThenCommitCommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentSchemePublicParametersGen;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;


@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class DamgardTechniqueTest {

    private int n = 3;
    private int m = 2;
    private Zp zp;
    private Group[] groups;
    private Group[] secondGroups;
    private GeneralizedSchnorrProtocol protocolProver;
    // different prover-protocol for negative test cases
    private GeneralizedSchnorrProtocol secondProtocolProver;
    private GeneralizedSchnorrProtocol protocolVerifier;
    private PedersenPublicParameters pedersenPublicParameters;
    private DamgardTechnique damgardProver;
    // different prover-protocol for negative test cases
    private DamgardTechnique secondDamgardProver;
    private DamgardTechnique damgardVerifier;
    private PedersenCommitmentScheme pedersenCommitmentScheme;
    private HashThenCommitCommitmentScheme hashThenCommitCommitmentScheme;

    @BeforeAll
    public void setUp() {
        GenSchnorrTestdataProvider provider = new GenSchnorrTestdataProvider();
        groups = provider.generateGenSchnorrGroups();
        zp = provider.generateGenSchnorrZPGroup(groups[0]);
        protocolProver = provider.getGenSchorrProtocol(m, n, groups);
        do {
            secondProtocolProver = provider.getGenSchorrProtocol(m, n, groups);
        } while (protocolProver.equals(secondProtocolProver));
        protocolVerifier = new GeneralizedSchnorrProtocol((GeneralizedSchnorrProblem[]) protocolProver.getProblems(),
                null, (GeneralizedSchnorrPublicParameter) protocolProver.getPublicParameters());

        PedersenCommitmentSchemePublicParametersGen pedersenCommitmentSchemePublicParametersGen = new
                PedersenCommitmentSchemePublicParametersGen();

        pedersenPublicParameters = pedersenCommitmentSchemePublicParametersGen.setup(260, 1, true);
        pedersenCommitmentScheme = new PedersenCommitmentScheme(pedersenPublicParameters);
        hashThenCommitCommitmentScheme = new HashThenCommitCommitmentScheme(pedersenCommitmentScheme, new
                SHA256HashFunction());
        damgardProver = new DamgardTechnique(protocolProver, hashThenCommitCommitmentScheme);
        secondDamgardProver = new DamgardTechnique(secondProtocolProver, hashThenCommitCommitmentScheme);
        damgardVerifier = new DamgardTechnique(protocolVerifier, hashThenCommitCommitmentScheme);
    }

    /**
     * Positive test checking that for a correct protocol execution the verifier accepts.
     * The test is checking the protocol execution with internal randomness.
     */
    @Test
    public void testDamgardInternalRandomness() {
        InteractiveThreeWayAoKTester.protocolExecutionInternalRandomnessTest(damgardProver, damgardVerifier);
    }

    /**
     * This negative test checks cases where the verify method is called with not matching parameters and therefore
     * should return false for internal randomness.
     */
    @Test
    public void testNeqDamgardInternalRandomness() {
        InteractiveThreeWayAoKTester.protocolExecutionInternalRandomnessNegativeTest(damgardProver, secondDamgardProver,
                damgardVerifier);
    }

    /**
     * This test checks the representation usage within the execution. In this case a correct protocol
     * execution is performed checking the representation for announcement, challenge and response; then a correct
     * protocol execution is performed checking the representation the Damgard's Technique itself.
     */
    /*@Test
    public void representationForProtocolExecutionTest() {
        // run test for checking representation for announcement, challenge and response
        InteractiveThreeWayAoKTester.representationForProtocolExecutionTest(damgardProver, damgardVerifier);
        // test representation of Damgard's Technique
        // serialize and deserialize Damgard's Technique
        DamgardTechnique damgardProver2 = new DamgardTechnique(damgardProver.getRepresentation());
        assertEquals(damgardProver, damgardProver2);

        // verify that execution is still correct
        Announcement[] a = damgardProver2.generateAnnouncements();
        Challenge c = damgardVerifier.chooseChallenge();
        Response[] r = damgardProver2.generateResponses(c);
        assertTrue(damgardVerifier.verify(a, c, r));
    }*/
    @Test
    public void recreateTest() {
        InteractiveThreeWayAoKTester.recreateTest(damgardProver, damgardVerifier);
    }
}
