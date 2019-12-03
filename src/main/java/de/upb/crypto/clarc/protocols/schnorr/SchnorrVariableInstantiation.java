package de.upb.crypto.clarc.protocols.schnorr;

import de.upb.crypto.clarc.protocols.SecretInput;
import de.upb.crypto.clarc.protocols.arguments.sigma.AnnouncementSecret;
import de.upb.crypto.clarc.protocols.arguments.sigma.Response;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.EscapingByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.math.BigInteger;
import java.util.Map;

public class SchnorrVariableInstantiation implements Response, SecretInput, AnnouncementSecret {
    @Represented
    protected Map<String, BigInteger> variableInstantiation;

    public SchnorrVariableInstantiation(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public SchnorrVariableInstantiation(Map<String, BigInteger> variableInstantiation) {
        this.variableInstantiation = variableInstantiation;
    }

    public BigInteger getValue(String name) {
        return variableInstantiation.get(name);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        variableInstantiation.keySet().stream()
                .sorted()
                .forEachOrdered(k -> byteAccumulator.escapeAndSeparate(variableInstantiation.get(k).toByteArray()));
        return byteAccumulator;
    }
}
