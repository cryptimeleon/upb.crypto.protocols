package de.upb.crypto.clarc.protocols.serialization.classes;

import de.upb.crypto.clarc.protocols.expressions.SimpleGroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.SimpleZnElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.SuperGroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.SuperZnElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.arith.*;
import de.upb.crypto.clarc.protocols.expressions.collectionexpressions.IntervalZnExpression;
import de.upb.crypto.clarc.protocols.expressions.comparison.*;
import de.upb.crypto.craco.interfaces.policy.PolicyFact;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.interfaces.structures.RingAdditiveGroup;
import de.upb.crypto.math.structures.zn.RingMultiplication;
import de.upb.crypto.math.structures.zn.Zn;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class ExpressionTestdataProvider {


    public final String SMALL_PRIME_NUMBER = "11";
    private final SimpleZnElementPolicyFacts znFacts;
    private final SimpleGroupElementPolicyFacts groupFacts;

    private final Zp zpForArithExpr;
    private final Zn.ZnElement twoZp;
    private final Zn.ZnElement threeZp;
    private final Zn.ZnElement fourZp;
    private final Zn.ZnElement sixZp;
    private final Zn.ZnElement eightZp;
    private final ZnVariable var2Zp;
    private final ZnVariable var3Zp;
    private final ZnVariable var4Zp;
    private final ZnVariable var6Zp;
    private final ZnVariable var8Zp;
    private final NumberZnElementLiteral const2Zp;
    private final NumberZnElementLiteral const3Zp;
    private final NumberZnElementLiteral const4Zp;
    private final NumberZnElementLiteral const8Zp;

    private final HashMap<String, Zn.ZnElement> valueMapZp;

    private final RingAdditiveGroup.RingAdditiveGroupElement twoGroup;

    private final RingAdditiveGroup.RingAdditiveGroupElement threeGroup;
    private final RingAdditiveGroup.RingAdditiveGroupElement fourGroup;
    private final RingAdditiveGroup.RingAdditiveGroupElement fiveGroup;
    private final RingAdditiveGroup.RingAdditiveGroupElement sixGroup;
    private final RingAdditiveGroup.RingAdditiveGroupElement eightGroup;

    private final GroupElementVariable var2Group;
    private final GroupElementVariable var3Group;
    private final NumberGroupElementLiteral const2Group;
    private final NumberGroupElementLiteral const4Group;

    private final Map<String, GroupElement> valueMapGroup;


    private final List<PolicyFact> facts;


    public ExpressionTestdataProvider() {
        zpForArithExpr = new Zp(new BigInteger(SMALL_PRIME_NUMBER));
        twoGroup = zpForArithExpr.createZnElement(BigInteger.valueOf(2)).toAdditiveGroupElement();
        threeGroup = zpForArithExpr.createZnElement(BigInteger.valueOf(3)).toAdditiveGroupElement();
        fourGroup = zpForArithExpr.createZnElement(BigInteger.valueOf(4)).toAdditiveGroupElement();
        fiveGroup = zpForArithExpr.createZnElement(BigInteger.valueOf(5)).toAdditiveGroupElement();
        sixGroup = zpForArithExpr.createZnElement(BigInteger.valueOf(6)).toAdditiveGroupElement();
        eightGroup = zpForArithExpr.createZnElement(BigInteger.valueOf(8)).toAdditiveGroupElement();

        var2Group = new GroupElementVariable("twoGroup");
        var3Group = new GroupElementVariable("threeGroup");
        const2Group = new NumberGroupElementLiteral(twoGroup);
        const4Group = new NumberGroupElementLiteral(fourGroup);

        valueMapGroup = new HashMap<>();
        valueMapGroup.put("twoGroup", twoGroup);
        valueMapGroup.put("threeGroup", threeGroup);

        twoZp = zpForArithExpr.createZnElement(BigInteger.valueOf(2));
        threeZp = zpForArithExpr.createZnElement(BigInteger.valueOf(3));
        fourZp = zpForArithExpr.createZnElement(BigInteger.valueOf(4));
        sixZp = zpForArithExpr.createZnElement(BigInteger.valueOf(6));
        eightZp = zpForArithExpr.createZnElement(BigInteger.valueOf(8));
        var2Zp = new ZnVariable("twoZp");
        var3Zp = new ZnVariable("threeZp");
        var4Zp = new ZnVariable("fourZp");
        var6Zp = new ZnVariable("sixZp");
        var8Zp = new ZnVariable("eightZp");
        const2Zp = new NumberZnElementLiteral(twoZp);
        const3Zp = new NumberZnElementLiteral(threeZp);
        const4Zp = new NumberZnElementLiteral(fourZp);
        const8Zp = new NumberZnElementLiteral(eightZp);

        valueMapZp = new HashMap<>();
        valueMapZp.put("twoZp", twoZp);
        valueMapZp.put("threeZp", threeZp);
        valueMapZp.put("fourZp", fourZp);
        valueMapZp.put("sixZp", sixZp);
        valueMapZp.put("eightZp", eightZp);

        facts = new ArrayList<>();

        znFacts = new SimpleZnElementPolicyFacts(valueMapZp);
        groupFacts = new SimpleGroupElementPolicyFacts(valueMapGroup);
        facts.add(znFacts);
        facts.add(groupFacts);
    }


    public SimpleZnElementPolicyFacts getZnFacts() {
        return znFacts;
    }


    public SimpleGroupElementPolicyFacts getGroupFacts() {
        return groupFacts;
    }

    public ArithZnElementExpression getAdditionZnExpression() {
        List<ArithZnElementExpression> addInput = new ArrayList<>();
        addInput.add(var2Zp);
        addInput.add(const4Zp);
        return new AdditionZnExpression(addInput);
    }

    public SubtractionExpression getSubtractionExpression() {
        List<ArithZnElementExpression> subInput = new ArrayList<>();
        subInput.add(const8Zp);
        subInput.add(var4Zp);
        return new SubtractionZnExpression(subInput);
    }

    public MultiplicationZnExpression getMultiplicationZnExpression() {
        List<ArithZnElementExpression> mulInput = new ArrayList<>();
        mulInput.add(const2Zp);
        mulInput.add(var3Zp);
        return new MultiplicationZnExpression(mulInput);
    }

    public DivisionZnExpression getDivisionZnExpression() {
        List<ArithZnElementExpression> divInput = new ArrayList<>();
        divInput.add(const8Zp);
        divInput.add(var4Zp);
        return new DivisionZnExpression(divInput);
    }

    public InverseZnExpression getInverseZnExpression() {
        return new InverseZnExpression(var3Zp);
    }

    public PowerZnExpression getPowerZnExpression() {
        return new PowerZnExpression(var2Zp, const3Zp);
    }

    public SumZnExpression getSumZnExpression() {
        List<ArithZnElementExpression> sumInput = new ArrayList<>();
        sumInput.add(var2Zp);
        sumInput.add(const4Zp);
        return new SumZnExpression(sumInput);
    }


    public ProductZnExpression getProductZnExpression() {
        List<ArithZnElementExpression> prodInput = new ArrayList<>();
        prodInput.add(const2Zp);
        prodInput.add(var3Zp);
        return new ProductZnExpression(prodInput);
    }

    public InverseGroupElementExpression getInverseGroupElementExpression() {
        return new InverseGroupElementExpression(var3Group);
    }

    public PowerGroupElementExpression getPowerGroupElementExpression() {
        return new PowerGroupElementExpression(var2Group, const3Zp);
    }


    public ProductGroupElementExpression getProductGroupElementExpression() {
        List<ArithGroupElementExpression> prodInput = new ArrayList<>();
        prodInput.add(const2Group);
        prodInput.add(var3Group);
        return new ProductGroupElementExpression(prodInput);
    }

    public PairingGroupElementExpression getPairingGroupElementExpression() {
        BilinearMap map = new RingMultiplication(zpForArithExpr);
        NumberGroupElementLiteral varAdd3 = new NumberGroupElementLiteral(zpForArithExpr.createZnElement(BigInteger
                .valueOf(3))
                .toAdditiveGroupElement());
        NumberGroupElementLiteral varAdd2 = new NumberGroupElementLiteral(zpForArithExpr.createZnElement(BigInteger
                .valueOf(2))
                .toAdditiveGroupElement());
        return new PairingGroupElementExpression(map, varAdd3, varAdd2);
    }


    public GroupElementEqualityExpression getGroupElementEqualityExpression() {
        List<ArithGroupElementExpression> prodInput = new ArrayList<>();
        prodInput.add(const2Group);
        prodInput.add(var3Group);
        ProductGroupElementExpression prod = new ProductGroupElementExpression(prodInput);

        List<ArithGroupElementExpression> prodInput2 = new ArrayList<>();
        prodInput2.add(var3Group);
        prodInput2.add(const2Group);
        ProductGroupElementExpression prod2 = new ProductGroupElementExpression(prodInput2);

        return new GroupElementEqualityExpression(prod, prod2);
    }

    public GroupElementInequalityExpression getGroupElementInequalityExpression() {
        List<ArithGroupElementExpression> prodInput = new ArrayList<>();
        prodInput.add(const2Group);
        prodInput.add(var3Group);
        ProductGroupElementExpression prod = new ProductGroupElementExpression(prodInput);


        List<ArithGroupElementExpression> prodInput2 = new ArrayList<>();
        prodInput2.add(var3Group);
        prodInput2.add(const2Group);
        ProductGroupElementExpression prod2 = new ProductGroupElementExpression(prodInput2);

        return new GroupElementInequalityExpression(prod, prod2);
    }

    public ZnElementEqualityExpression getZnElementEqualityExpression() {
        List<ArithZnElementExpression> addInput = new ArrayList<>();
        addInput.add(var2Zp);
        addInput.add(const4Zp);
        ArithZnElementExpression add = new AdditionZnExpression(addInput);

        List<ArithZnElementExpression> mulInput = new ArrayList<>();
        mulInput.add(var2Zp);
        mulInput.add(var3Zp);
        MultiplicationZnExpression mul = new MultiplicationZnExpression(mulInput);

        return new ZnElementEqualityExpression(add, mul);
    }

    public ZnElementInequalityExpression getZnElementInequalityExpression() {
        List<ArithZnElementExpression> addInput = new ArrayList<>();
        addInput.add(var2Zp);
        addInput.add(const4Zp);
        ArithZnElementExpression add = new AdditionZnExpression(addInput);

        List<ArithZnElementExpression> mulInput = new ArrayList<>();
        mulInput.add(var2Zp);
        mulInput.add(var3Zp);
        MultiplicationZnExpression mul = new MultiplicationZnExpression(mulInput);

        return new ZnElementInequalityExpression(add, mul);
    }


    public Zp getZpForArithExpr() {
        return zpForArithExpr;
    }

    public Zn.ZnElement getTwoZp() {
        return twoZp;
    }

    public Zn.ZnElement getThreeZp() {
        return threeZp;
    }

    public Zn.ZnElement getFourZp() {
        return fourZp;
    }

    public Zn.ZnElement getSixZp() {
        return sixZp;
    }

    public Zn.ZnElement getEightZp() {
        return eightZp;
    }

    public ZnVariable getVar2Zp() {
        return var2Zp;
    }

    public ZnVariable getVar3Zp() {
        return var3Zp;
    }

    public ZnVariable getVar4Zp() {
        return var4Zp;
    }

    public ZnVariable getVar6Zp() {
        return var6Zp;
    }

    public ZnVariable getVar8Zp() {
        return var8Zp;
    }

    public NumberZnElementLiteral getConst2Zp() {
        return const2Zp;
    }

    public NumberZnElementLiteral getConst3Zp() {
        return const3Zp;
    }

    public NumberZnElementLiteral getConst4Zp() {
        return const4Zp;
    }

    public NumberZnElementLiteral getConst8Zp() {
        return const8Zp;
    }

    public HashMap<String, Zn.ZnElement> getValueMapZp() {
        return valueMapZp;
    }

    public RingAdditiveGroup.RingAdditiveGroupElement getTwoGroup() {
        return twoGroup;
    }

    public RingAdditiveGroup.RingAdditiveGroupElement getThreeGroup() {
        return threeGroup;
    }

    public RingAdditiveGroup.RingAdditiveGroupElement getFourGroup() {
        return fourGroup;
    }

    public RingAdditiveGroup.RingAdditiveGroupElement getFiveGroup() {
        return fiveGroup;
    }

    public RingAdditiveGroup.RingAdditiveGroupElement getSixGroup() {
        return sixGroup;
    }

    public RingAdditiveGroup.RingAdditiveGroupElement getEightGroup() {
        return eightGroup;
    }

    public GroupElementVariable getVar2Group() {
        return var2Group;
    }

    public GroupElementVariable getVar3Group() {
        return var3Group;
    }

    public NumberGroupElementLiteral getConst2Group() {
        return const2Group;
    }

    public NumberGroupElementLiteral getConst4Group() {
        return const4Group;
    }

    public Map<String, GroupElement> getValueMapGroup() {
        return valueMapGroup;
    }

    public List<PolicyFact> getFacts() {
        return facts;
    }

    public SuperGroupElementPolicyFacts getSuperGroupFacts() {

        List<SimpleGroupElementPolicyFacts> factsList = new ArrayList<>();
        factsList.add(this.groupFacts);
        return new SuperGroupElementPolicyFacts(factsList);
    }

    public SuperZnElementPolicyFacts getSuperZnFacts() {
        List<SimpleZnElementPolicyFacts> factsList = new ArrayList<>();
        factsList.add(znFacts);
        return new SuperZnElementPolicyFacts(factsList);
    }


    public Zp.ZpElement[] generateRandomArray(Zp zp, int length) {
        return Stream.generate(zp::getUniformlyRandomUnit).limit(length).toArray(Zp.ZpElement[]::new);
    }

    public IntervalZnExpression getIntervalZnExpression(BigInteger lower, BigInteger upper) {
        return new IntervalZnExpression(lower, upper);
    }

    public ZnElementInCollectionComparisonExpression getInIntervalExoression() {
        return new ZnElementInCollectionComparisonExpression(this.const3Zp, this.getIntervalZnExpression(this
                .const2Zp.getValue().getInteger(), this.const8Zp.getValue().getInteger()));
    }
}
