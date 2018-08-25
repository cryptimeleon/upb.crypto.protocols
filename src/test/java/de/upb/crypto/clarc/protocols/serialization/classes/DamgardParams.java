package de.upb.crypto.clarc.protocols.serialization.classes;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.damgardtechnique.DamgardTechnique;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GenSchnorrTestdataProvider;
import de.upb.crypto.clarc.utils.StandaloneTestParams;
import de.upb.crypto.craco.commitment.HashThenCommitCommitmentScheme;
import de.upb.crypto.craco.commitment.interfaces.CommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentSchemePublicParametersGen;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.math.hash.impl.VariableOutputLengthHashFunction;
import de.upb.crypto.math.interfaces.hash.HashFunction;
import de.upb.crypto.math.interfaces.structures.Group;

import java.util.ArrayList;
import java.util.Collection;

public class DamgardParams {


    public static Collection<StandaloneTestParams> get() {
        GenSchnorrTestdataProvider providerGenSchnorr = new GenSchnorrTestdataProvider();

        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();

        int numberOfMessages = 1;

        PedersenCommitmentSchemePublicParametersGen pedersenCommitmentSchemePublicParametersGen = new
                PedersenCommitmentSchemePublicParametersGen();
        PedersenPublicParameters pedersenPublicParameters = pedersenCommitmentSchemePublicParametersGen.setup(260,
                numberOfMessages, true);
        Group[] zp = {pedersenPublicParameters.getGroup()};

        HashFunction hashFunction = new VariableOutputLengthHashFunction(
                pedersenPublicParameters.getZp().upperBoundForUniqueRepresentation() - 1);

        CommitmentScheme commitmentScheme = new HashThenCommitCommitmentScheme(new PedersenCommitmentScheme
                (pedersenPublicParameters),
                hashFunction);

        toReturn.add(new StandaloneTestParams(DamgardTechnique.class, getDamgardTechnique(providerGenSchnorr
                .getGenSchorrProtocol(1, numberOfMessages, zp), commitmentScheme)));


        return toReturn;
    }

    static DamgardTechnique getDamgardTechnique(SigmaProtocol protocol, CommitmentScheme commitmentScheme) {
        DamgardTechnique damgardTechnique = new DamgardTechnique(protocol, commitmentScheme);
        damgardTechnique.generateAnnouncements();
        return damgardTechnique;
    }
}
