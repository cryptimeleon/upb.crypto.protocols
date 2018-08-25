package de.upb.crypto.clarc.protocols;

import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.clarc.protocols.expressions.comparison.ZnElementEqualityExpression;
import de.upb.crypto.clarc.protocols.serialization.classes.ExpressionTestdataProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static org.junit.jupiter.api.Assertions.assertEquals;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class EqualityComparisonExpressionTest {


    private ExpressionTestdataProvider provider;

    @BeforeAll
    public void setUp() {
        provider = new ExpressionTestdataProvider();
    }

    @Test
    public void ZnEqualComparisonTest() {
        assertEquals(true, provider.getZnElementEqualityExpression().isFulfilled(provider.getFacts()),
                "The given values are equal , thus the check should not fail");
    }

    @Test
    public void GroupEqualExpressionTest() {
        assertEquals(true, provider.getGroupElementEqualityExpression().isFulfilled(provider.getFacts()),
                "The given values are equal, thus the check should not fail");
    }

    @Test
    public void ZnNotEqualComparisonTest() {
        ZnElementEqualityExpression znElementEqualityExpression = provider.getZnElementEqualityExpression();
        znElementEqualityExpression.setLhs(provider.getConst4Zp());
        assertEquals(false, znElementEqualityExpression.isFulfilled(provider.getFacts()),
                "The given values are not equal, thus the check should fail");
    }

    @Test
    public void GroupNotEqualExpressionTest() {
        GroupElementEqualityExpression groupElementEqualityExpression = provider
                .getGroupElementEqualityExpression();
        groupElementEqualityExpression.setLhs(provider.getConst2Group());
        assertEquals(false, groupElementEqualityExpression.isFulfilled(provider.getFacts()),
                "The given values are not equal, thus the check should fail");
    }


}
