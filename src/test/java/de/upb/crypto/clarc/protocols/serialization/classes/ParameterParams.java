package de.upb.crypto.clarc.protocols.serialization.classes;

import de.upb.crypto.clarc.protocols.parameters.EmptyProblem;
import de.upb.crypto.clarc.protocols.parameters.EmptyWitness;
import de.upb.crypto.clarc.utils.StandaloneTestParams;

import java.util.ArrayList;
import java.util.Collection;

public class ParameterParams {

    public static Collection<StandaloneTestParams> get() {

        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();

        toReturn.add(new StandaloneTestParams(EmptyWitness.class, new EmptyWitness("test")));

        toReturn.add(new StandaloneTestParams(EmptyProblem.class, new EmptyProblem()));

        return toReturn;
    }
}
