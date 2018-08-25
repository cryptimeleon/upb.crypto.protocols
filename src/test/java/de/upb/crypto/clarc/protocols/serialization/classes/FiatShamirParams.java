package de.upb.crypto.clarc.protocols.serialization.classes;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.FiatShamirHeuristic;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.FiatShamirSignatureScheme;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirProof;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GenSchnorrTestdataProvider;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocolProvider;
import de.upb.crypto.clarc.utils.StandaloneTestParams;
import de.upb.crypto.math.hash.impl.VariableOutputLengthHashFunction;
import de.upb.crypto.math.interfaces.hash.HashFunction;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.ArrayList;
import java.util.Collection;

public class FiatShamirParams {

    public static Collection<StandaloneTestParams> get() {
        int m = 2;
        int n = 3;

        GenSchnorrTestdataProvider providerGenSchnorr = new GenSchnorrTestdataProvider();

        Group[] groups = providerGenSchnorr.generateGenSchnorrGroups();

        HashFunction hashFunction = new VariableOutputLengthHashFunction(providerGenSchnorr.generateGenSchnorrZPGroup
                (groups[0]).upperBoundForUniqueRepresentation() - 1);

        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();

        final FiatShamirHeuristic fiatShamirHeuristic =
                getFiatShamirHeuristic(providerGenSchnorr.getGenSchorrProtocol(m, n, groups), hashFunction);
        toReturn.add(new StandaloneTestParams(FiatShamirHeuristic.class, fiatShamirHeuristic));
        toReturn.add(new StandaloneTestParams(FiatShamirProof.class, fiatShamirHeuristic.prove()));
        toReturn.add(new StandaloneTestParams(FiatShamirSignatureScheme.class,
                getFiatShamirSignatureScheme(providerGenSchnorr.generateGenSchnorrZPGroup(groups[0]), hashFunction)));

        return toReturn;
    }

    static FiatShamirHeuristic getFiatShamirHeuristic(SigmaProtocol protocol, HashFunction hashFunction) {
        return new FiatShamirHeuristic(protocol, hashFunction);
    }

    public static FiatShamirSignatureScheme getFiatShamirSignatureScheme(Zp zp, HashFunction hashFunction) {
        return new FiatShamirSignatureScheme(new GeneralizedSchnorrProtocolProvider(zp), hashFunction);
    }
}
