package de.upb.crypto.clarc.protocols;

import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementInequalityExpression;
import de.upb.crypto.clarc.protocols.expressions.comparison.ZnElementInequalityExpression;
import de.upb.crypto.clarc.protocols.serialization.classes.ExpressionTestdataProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static org.junit.jupiter.api.Assertions.assertEquals;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class InequalityComparisonExpressionTest {

    private ExpressionTestdataProvider provider;

    @BeforeAll
    public void setUp() {
        provider = new ExpressionTestdataProvider();
    }

    @Test
    public void ZnEqualComparisonTest() {
        assertEquals(false, provider.getZnElementInequalityExpression().isFulfilled(provider.getFacts()),
                "The given values are not equal , thus the check should fail");
    }

    @Test
    public void GroupEqualExpressionTest() {
        assertEquals(true, provider.getGroupElementEqualityExpression().isFulfilled(provider.getFacts()),
                "The given values are equal, thus the check should succeed");
    }

    @Test
    public void ZnNotEqualComparisonTest() {
        ZnElementInequalityExpression znElementInequalityExpression = provider.getZnElementInequalityExpression();
        znElementInequalityExpression.setLhs(provider.getConst4Zp());
        assertEquals(true, znElementInequalityExpression.isFulfilled(provider.getFacts()),
                "The given values are  equal, thus the check should   not fail");
    }

    @Test
    public void GroupNotEqualExpressionTest() {
        GroupElementInequalityExpression groupElementInequalityExpression = provider
                .getGroupElementInequalityExpression();
        groupElementInequalityExpression.setLhs(provider.getConst2Group());
        assertEquals(true, groupElementInequalityExpression.isFulfilled(provider.getFacts()),
                "The given values are  equal, thus the check should not fail");
    }


}
