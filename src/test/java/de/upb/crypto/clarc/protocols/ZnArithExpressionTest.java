package de.upb.crypto.clarc.protocols;

import de.upb.crypto.clarc.protocols.serialization.classes.ExpressionTestdataProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static org.junit.jupiter.api.Assertions.assertEquals;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class ZnArithExpressionTest {

    private ExpressionTestdataProvider provider;

    @BeforeAll
    public void setUp() {
        provider = new ExpressionTestdataProvider();

    }

    @Test
    public void simpleNumberElementTest() {
        assertEquals(provider.getFourZp(), provider.getConst4Zp().calculateResult(
                provider.getGroupFacts(), provider.getZnFacts()));
    }

    @Test
    public void simpleVariableTest() {
        assertEquals(provider.getSixZp(), provider.getVar6Zp().calculateResult(
                provider.getGroupFacts(), provider.getZnFacts()));
    }

    @Test
    public void simpleAddTest() {
        assertEquals(provider.getSixZp(), provider.getAdditionZnExpression().calculateResult(
                provider.getGroupFacts(), provider.getZnFacts()));
    }


    @Test
    public void simpleSubTest() {

        assertEquals(provider.getFourZp(), provider.getSubtractionExpression().calculateResult(
                provider.getGroupFacts(), provider.getZnFacts()));
    }


    @Test
    public void simpleMulTest() {
        assertEquals(provider.getSixZp(), provider.getMultiplicationZnExpression().calculateResult(
                provider.getGroupFacts(), provider.getZnFacts()));
    }


    @Test
    public void simpleDivTest() {
        assertEquals(provider.getTwoZp(), provider.getDivisionZnExpression().calculateResult(
                provider.getGroupFacts(), provider.getZnFacts()));
    }

    @Test
    public void simpleInvertTest() {
        assertEquals(provider.getFourZp(), provider.getInverseZnExpression().calculateResult(
                provider.getGroupFacts(), provider.getZnFacts()));
    }


    @Test
    public void simplePowerTest() {
        assertEquals(provider.getEightZp(), provider.getPowerZnExpression().calculateResult(
                provider.getGroupFacts(), provider.getZnFacts()));
    }


    @Test
    public void simpleSumExprTest() {
        assertEquals(provider.getSixZp(), provider.getSumZnExpression().calculateResult(provider.getGroupFacts(),
                provider.getZnFacts()));
    }


    @Test
    public void simpleProductTest() {
        assertEquals(provider.getSixZp(), provider.getProductZnExpression().calculateResult(provider.getGroupFacts(),
                provider.getZnFacts()));
    }


}
