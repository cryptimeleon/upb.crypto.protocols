package de.upb.crypto.clarc.protocols.arguments.schnorr2;

import de.upb.crypto.clarc.protocols.arguments.sigma.Challenge;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.BigIntegerRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.math.BigInteger;

public class SchnorrChallenge implements Challenge {
    protected BigInteger challenge;

    public SchnorrChallenge(Representation repr) {
        challenge = repr.bigInt().get();
    }

    public SchnorrChallenge(BigInteger challenge) {
        this.challenge = challenge;
    }

    public BigInteger getChallenge() {
        return challenge;
    }

    @Override
    public Representation getRepresentation() {
        return new BigIntegerRepresentation(challenge);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        byteAccumulator.append(challenge.toByteArray());
        return byteAccumulator;
    }
}
