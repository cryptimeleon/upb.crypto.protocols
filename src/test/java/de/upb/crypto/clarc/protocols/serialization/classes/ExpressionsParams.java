package de.upb.crypto.clarc.protocols.serialization.classes;

import de.upb.crypto.clarc.protocols.expressions.SimpleGroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.SimpleZnElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.SuperGroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.SuperZnElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.arith.*;
import de.upb.crypto.clarc.protocols.expressions.collectionexpressions.IntervalZnExpression;
import de.upb.crypto.clarc.protocols.expressions.comparison.*;
import de.upb.crypto.clarc.utils.StandaloneTestParams;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;

public class ExpressionsParams {
    public static Collection<StandaloneTestParams> get() {
        ExpressionTestdataProvider provider = new ExpressionTestdataProvider();

        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();

        toReturn.add(new StandaloneTestParams(AdditionZnExpression.class, provider.getAdditionZnExpression()));
        toReturn.add(new StandaloneTestParams(DivisionZnExpression.class, provider.getDivisionZnExpression()));
        toReturn.add(new StandaloneTestParams(GroupElementVariable.class, provider.getVar2Group()));
        toReturn.add(new StandaloneTestParams(InverseGroupElementExpression.class, provider
                .getInverseGroupElementExpression()));
        toReturn.add(new StandaloneTestParams(InverseZnExpression.class, provider.getInverseZnExpression()));
        toReturn.add(new StandaloneTestParams(MultiplicationZnExpression.class, provider
                .getMultiplicationZnExpression()));
        toReturn.add(new StandaloneTestParams(NumberGroupElementLiteral.class, provider.getConst2Group()));
        toReturn.add(new StandaloneTestParams(NumberZnElementLiteral.class, provider.getConst2Zp()));
        toReturn.add(new StandaloneTestParams(PairingGroupElementExpression.class, provider
                .getPairingGroupElementExpression()));
        toReturn.add(new StandaloneTestParams(PowerGroupElementExpression.class, provider
                .getPowerGroupElementExpression()));
        toReturn.add(new StandaloneTestParams(PowerZnExpression.class, provider.getPowerZnExpression()));
        toReturn.add(new StandaloneTestParams(ProductGroupElementExpression.class, provider
                .getProductGroupElementExpression()));
        toReturn.add(new StandaloneTestParams(ProductZnExpression.class, provider.getProductZnExpression()));
        toReturn.add(new StandaloneTestParams(SubtractionZnExpression.class, provider.getSubtractionExpression()));
        toReturn.add(new StandaloneTestParams(SumZnExpression.class, provider.getSumZnExpression()));
        toReturn.add(new StandaloneTestParams(ZnVariable.class, provider.getVar2Zp()));
        toReturn.add(new StandaloneTestParams(SimpleGroupElementPolicyFacts.class, provider.getGroupFacts()));
        toReturn.add(new StandaloneTestParams(SimpleZnElementPolicyFacts.class, provider.getZnFacts()));
        toReturn.add(new StandaloneTestParams(SuperGroupElementPolicyFacts.class, provider.getSuperGroupFacts()));
        toReturn.add(new StandaloneTestParams(SuperZnElementPolicyFacts.class, provider.getSuperZnFacts()));
        toReturn.add(new StandaloneTestParams(GroupElementEqualityExpression.class, provider
                .getGroupElementEqualityExpression()));
        toReturn.add(new StandaloneTestParams(ZnElementEqualityExpression.class, provider
                .getZnElementEqualityExpression()));
        toReturn.add(new StandaloneTestParams(GroupElementInequalityExpression.class, provider
                .getGroupElementInequalityExpression()));
        toReturn.add(new StandaloneTestParams(ZnElementInequalityExpression.class, provider
                .getZnElementInequalityExpression()));

        toReturn.add(new StandaloneTestParams(IntervalZnExpression.class, provider.getIntervalZnExpression(BigInteger
                .valueOf(2), BigInteger.valueOf(8))));
        toReturn.add(new StandaloneTestParams(ZnElementInCollectionComparisonExpression.class, provider
                .getInIntervalExoression()));


        toReturn.add(new StandaloneTestParams(TautologyExpression.class, new TautologyExpression()));


        return toReturn;
    }
}
