package de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl;

import de.upb.crypto.clarc.protocols.fiatshamirtechnique.FiatShamirSignatureScheme;
import de.upb.crypto.clarc.protocols.parameters.Problem;
import de.upb.crypto.craco.interfaces.signature.SigningKey;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;

import java.util.Arrays;

/**
 * A {@link SigningKey} for the {@link FiatShamirSignatureScheme}.
 * <p>
 * It is composed of an {@link Problem}-{@link Witness}-pair.
 */
public class FiatShamirSigningKey implements SigningKey {
    @RepresentedArray(elementRestorer = @Represented)
    private Problem[] instance;
    @RepresentedArray(elementRestorer = @Represented)
    private Witness[] witness;

    public FiatShamirSigningKey(Problem[] instance, Witness[] witness) {
        this.instance = instance;
        this.witness = witness;
    }

    public FiatShamirSigningKey(Representation repr) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
    }

    public Problem[] getInstance() {
        return instance;
    }

    public Witness[] getWitness() {
        return witness;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FiatShamirSigningKey that = (FiatShamirSigningKey) o;
        return Arrays.equals(getInstance(), that.getInstance()) &&
                Arrays.equals(getWitness(), that.getWitness());
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(getInstance());
        result = 31 * result + Arrays.hashCode(getWitness());
        return result;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }
}
