package de.upb.crypto.clarc.protocols.generalizedschnorrprotocol;

import de.upb.crypto.clarc.protocols.InteractiveThreeWayAoKTester;
import de.upb.crypto.clarc.protocols.expressions.comparison.ArithComparisonExpression;
import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.clarc.protocols.protocolfactory.GeneralizedSchnorrProtocolFactory;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class GenSchnorrFactoryTest {

    private BigInteger small_prime;
    private int lamda = 260;
    private int n = 3;
    private int m = 2;
    private Zp zp;
    private Group[] groups;
    private GeneralizedSchnorrProtocol protocolProver;
    private GeneralizedSchnorrProtocol protocolVerifier;
    private GeneralizedSchnorrProtocol protocolProverWithReducedProblemDesc;


    @BeforeAll
    public void setUp() {
        GenSchnorrTestdataProvider provider = new GenSchnorrTestdataProvider();
        groups = provider.generateGenSchnorrGroups();
        zp = provider.generateGenSchnorrZPGroup(groups[0]);
        GeneralizedSchnorrWitnessNew witnesses = provider.getGenSchnorrWitness(n, zp);
        GeneralizedSchnorrProblem[] problems = provider.getGenSchnorrProblem(m, n, groups, provider.getGenerators(m,
                n, groups), witnesses);

        HashMap<String, Zp.ZpElement> witnessMapping = new HashMap<>();
        for (int i = 0; i < witnesses.getNumberOfWitnesses(); i++) {
            witnessMapping.put("x".concat(Integer.toString(i)), witnesses.getWitnessValue("x".concat(Integer.toString(i))));
        }
        ArithComparisonExpression[] equations = Arrays.stream(problems).map
                (GeneralizedSchnorrProblem::getProblemEquation).toArray(GroupElementEqualityExpression[]::new);
        GeneralizedSchnorrProtocolFactory factory = new GeneralizedSchnorrProtocolFactory(equations, zp);
        protocolProver = factory.createProverGeneralizedSchnorrProtocol(witnessMapping);
        protocolVerifier = factory.createVerifierGeneralizedSchnorrProtocol();

        //Remove at the first problem equation the last element
        /*ProductGroupElementExpression rhsToModify = ((ProductGroupElementExpression) problems[0].getProblemEquation()
                                                                                                .getRHS());
        List<ArithGroupElementExpression> elements =
                new ArrayList<>(rhsToModify.getElements());
        elements.remove(witnesses.getNumberOfWitnesses() - 1);
        rhsToModify.setElements(elements.stream().map(ele -> ((ArithExpression) ele)).collect(Collectors.toList()));
        problems[0].getProblemEquation().setRhs(rhsToModify);
        protocolProverWithReducedProblemDesc = factory.createProverGeneralizedSchnorrProtocol(witnessMapping);*/

    }

    @Test
    public void testGenSchnorrInternalRandomness() {
        InteractiveThreeWayAoKTester.protocolExecutionInternalRandomnessTest(protocolProver, protocolVerifier);
        assertArrayEquals(protocolVerifier.getProblems(), protocolProver.getProblems(),
                "The problems of the Generalized Schnorr protocols with internal randomness are inequal!");
    }

    /*@Test
    public void testCorrectGenerationWithReducedProblemDescr() {
        assertArrayEquals(protocolProver.getWitnesses(), protocolProverWithReducedProblemDesc.getWitnesses(),
                "The witnesses of the two protocols are not equal but where expected to be equal");
        //Check if the generator in the first row at the last position is set to the neutral element of G1
        assertEquals(protocolProverWithReducedProblemDesc.getPp().getGroups()[0].getNeutralElement(),
                protocolProverWithReducedProblemDesc.getPp().getGenerators()[0][protocolProverWithReducedProblemDesc
                        .getPp().getGenerators()[0].length - 1], "The element was expected to be the neural element");
    }*/

}
