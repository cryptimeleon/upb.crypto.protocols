package de.upb.crypto.clarc.protocols.arguments.setmembership;

import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.structures.zn.Zn;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Set;

public class SetMembershipPublicParameters implements Representable {
    BilinearGroup bilinearGroup;
    @Represented(restorer = "G1")
    GroupElement g1;
    @Represented(restorer = "G2")
    GroupElement g2;
    @Represented(restorer = "G2")
    GroupElement pk;
    @Represented(restorer = "int -> G1")
    HashMap<BigInteger, GroupElement> signatures;
    GroupElement egg;

    public SetMembershipPublicParameters(BilinearGroup bilinearGroup, GroupElement g1, GroupElement g2, GroupElement pk, HashMap<BigInteger, GroupElement> signatures) {
        this.bilinearGroup = bilinearGroup;
        this.g1 = g1;
        this.g2 = g2;
        this.pk = pk;
        this.signatures = signatures;
        this.egg = bilinearGroup.getBilinearMap().apply(g1, g2);
    }

    public SetMembershipPublicParameters(BilinearGroup group, Representation repr) {
        this.bilinearGroup = group;
        new ReprUtil(this).register(group).deserialize(repr);
        this.egg = bilinearGroup.getBilinearMap().apply(g1, g2);
    }

    public static SetMembershipPublicParameters generate(BilinearGroup group, Set<BigInteger> set) {
        GroupElement g1 = group.getG1().getUniformlyRandomNonNeutral();
        GroupElement g2 = group.getG2().getUniformlyRandomNonNeutral();
        Zn.ZnElement sk = group.getG1().getUniformlyRandomExponent();
        GroupElement pk = g2.pow(sk);
        HashMap<BigInteger, GroupElement> signatures = new HashMap<>();
        for (BigInteger i : set)
            signatures.put(i, g1.pow(sk.add(group.getZn().valueOf(i)).inv()));

        return new SetMembershipPublicParameters(group, g1, g2, pk, signatures);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public Zn getZn() {
        return g1.getStructure().getZn();
    }
}
