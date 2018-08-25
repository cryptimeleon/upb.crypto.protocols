package de.upb.crypto.clarc.protocols;

import de.upb.crypto.clarc.protocols.serialization.classes.ExpressionTestdataProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static org.junit.jupiter.api.Assertions.assertEquals;


@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class GroupElementArithExpressionTest {

    private ExpressionTestdataProvider provider;

    @BeforeAll
    public void setUp() {
        provider = new ExpressionTestdataProvider();
    }

    @Test
    public void simpleNumberElementTest() {

        assertEquals(provider.getFourGroup(), provider.getConst4Group().calculateResult(provider.getGroupFacts(),
                provider.getZnFacts()));
    }

    @Test
    public void simpleVariableTest() {

        assertEquals(provider.getThreeGroup(), provider.getVar3Group().calculateResult(provider.getGroupFacts(),
                provider.getZnFacts()));
    }


    @Test
    public void simpleInvertTest() {
        assertEquals(provider.getEightGroup(), provider.getInverseGroupElementExpression().calculateResult(
                provider.getGroupFacts(), provider.getZnFacts()));
    }


    /*@Test
    public void simplePowerTest() {
        assertEquals(provider.getEightGroup(), provider.getPowerGroupElementExpression().calculateResult(
                provider.getGroupFacts(), provider.getZnFacts()));
    }


    @Test
    public void simpleProductTest() {

        assertEquals(provider.getFiveGroup(), provider.getProductGroupElementExpression().calculateResult(
                provider.getGroupFacts(), provider.getZnFacts()));
    }


    @Test
    public void simplePairingTest() {
        assertEquals(provider.getSixGroup(), provider.getPairingGroupElementExpression().calculateResult(
                provider.getGroupFacts(), provider.getZnFacts()));


    }*/


}
