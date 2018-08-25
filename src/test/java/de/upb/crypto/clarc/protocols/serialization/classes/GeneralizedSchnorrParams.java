package de.upb.crypto.clarc.protocols.serialization.classes;

import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.*;
import de.upb.crypto.clarc.protocols.simulator.SigmaProtocolTranscript;
import de.upb.crypto.clarc.utils.StandaloneTestParams;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.ArrayList;
import java.util.Collection;

public class GeneralizedSchnorrParams {

    public static Collection<StandaloneTestParams> get() {
        int m = 2;
        int n = 3;
        GenSchnorrTestdataProvider providerGenSchnorr = new GenSchnorrTestdataProvider();


        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();


        Group[] groups = providerGenSchnorr.generateGenSchnorrGroups();
        Zp genSchnorrZp = providerGenSchnorr.generateGenSchnorrZPGroup(groups[0]);
        GeneralizedSchnorrWitnessNew witness =
                providerGenSchnorr.getGenSchnorrWitness(n, providerGenSchnorr.generateGenSchnorrZPGroup(groups[0]));
        GeneralizedSchnorrProtocol protocol = providerGenSchnorr.getGenSchorrProtocol(m, n, groups);
        GroupElement[][] generators = providerGenSchnorr.getGenerators(m, n, groups);

        toReturn.add(new StandaloneTestParams(GeneralizedSchnorrProblem.class, providerGenSchnorr
                .getGenSchnorrProblem(m, n, groups, generators, witness)[0]));
        toReturn.add(new StandaloneTestParams(GeneralizedSchnorrWitnessNew.class, witness));
        toReturn.add(new StandaloneTestParams(GeneralizedSchnorrWitness.class, new GeneralizedSchnorrWitness(genSchnorrZp.getOneElement(), "bar")));
        toReturn.add(new StandaloneTestParams(GeneralizedSchnorrProtocol.class, protocol));
        toReturn.add(new StandaloneTestParams(GeneralizedSchnorrPublicParameter.class, providerGenSchnorr
                .getGenSchnorrPP(groups, generators, n, genSchnorrZp)));

        toReturn.add(new StandaloneTestParams(SigmaProtocolTranscript.class, protocol.getSimulator().simulate(
                new GeneralizedSchnorrChallenge(genSchnorrZp.getUniformlyRandomUnit())
        )));
        toReturn.add(new StandaloneTestParams(GeneralizedSchnorrProtocolProvider.class,
                new GeneralizedSchnorrProtocolProvider(genSchnorrZp)));

        return toReturn;
    }
}
