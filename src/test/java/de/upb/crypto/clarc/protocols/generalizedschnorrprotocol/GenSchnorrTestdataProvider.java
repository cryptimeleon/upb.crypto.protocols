package de.upb.crypto.clarc.protocols.generalizedschnorrprotocol;

import de.upb.crypto.clarc.protocols.expressions.arith.NumberGroupElementLiteral;
import de.upb.crypto.clarc.protocols.expressions.arith.PowerGroupElementExpression;
import de.upb.crypto.clarc.protocols.expressions.arith.ProductGroupElementExpression;
import de.upb.crypto.clarc.protocols.expressions.arith.ZnVariable;
import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.factory.BilinearGroupFactory;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.HashMap;

public class GenSchnorrTestdataProvider {

    public Group[] generateGenSchnorrGroups() {
        BilinearGroupFactory baseFactory = new BilinearGroupFactory(260);
        baseFactory.setRequirements(BilinearGroup.Type.TYPE_1);
        baseFactory.setDebugMode(true);
        BilinearMap bilinearMap = baseFactory.createBilinearGroup().getBilinearMap();

        return new Group[]{
                bilinearMap.getG1(),
                bilinearMap.getG2()
        };
    }


    public Zp generateGenSchnorrZPGroup(Group G1) {
        return new Zp(G1.size());
    }


    public GroupElement[][] getGenerators(int m, int n, Group[] groups) {


        GroupElement[][] generators = new GroupElement[m][n];
        for (int j = 0; j < m; j++) {
            for (int i = 0; i < n; i++) {
                generators[j][i] = groups[j].getUniformlyRandomNonNeutral();
            }
        }
        return generators;
    }

    public GeneralizedSchnorrPublicParameter getGenSchnorrPP(Group[] groups, GroupElement[][] generators, int n,
                                                             Zp zp) {
        return new GeneralizedSchnorrPublicParameter(zp.size());
    }

    public GeneralizedSchnorrWitnessNew getGenSchnorrWitness(int n, Zp zp) {
        HashMap<String, Zp.ZpElement> map = new HashMap<>();
        for (int i = 0; i < n; i++) {
            map.put("x" + Integer.toString(i), zp.getUniformlyRandomUnit());
        }
        return new GeneralizedSchnorrWitnessNew(map);
    }

    public GeneralizedSchnorrProblem[] getGenSchnorrProblem(int m, int n, Group[] groups, GroupElement[][] generators,
                                                            GeneralizedSchnorrWitnessNew witness) {
        GeneralizedSchnorrProblem[] problem = new GeneralizedSchnorrProblem[m];
        for (int j = 0; j < m; j++) {
            ProductGroupElementExpression rhs = new ProductGroupElementExpression();
            GroupElement Aj = groups[j].getNeutralElement();
            for (int i = 0; i < n; i++) {
                rhs.addElement(new PowerGroupElementExpression(new NumberGroupElementLiteral(generators[j][i]), new
                        ZnVariable("x".concat(String.valueOf(i)))));
                Aj = Aj.op(generators[j][i].pow(witness.getWitnessValue("x".concat(String.valueOf(i)))));
            }
            problem[j] = new GeneralizedSchnorrProblem(new GroupElementEqualityExpression(new
                    NumberGroupElementLiteral(Aj), rhs));
        }
        return problem;


    }


    public GeneralizedSchnorrProtocol getGenSchorrProtocol(int m, int n, Group[] groups) {
        GroupElement[][] generators = getGenerators(m, n, groups);
        GeneralizedSchnorrWitnessNew witness = getGenSchnorrWitness(n, generateGenSchnorrZPGroup(groups[0]));
        GeneralizedSchnorrPublicParameter pp = getGenSchnorrPP(groups, generators, n, generateGenSchnorrZPGroup
                (groups[0]));
        return new GeneralizedSchnorrProtocol(this.getGenSchnorrProblem(m, n, groups, generators, witness), witness,
                pp);

    }


}