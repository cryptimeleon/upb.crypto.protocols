package de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl;

import de.upb.crypto.clarc.protocols.fiatshamirtechnique.FiatShamirSignatureScheme;
import de.upb.crypto.clarc.protocols.parameters.Problem;
import de.upb.crypto.craco.interfaces.signature.VerificationKey;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;

import java.util.Arrays;

/**
 * A {@link VerificationKey} for the {@link FiatShamirSignatureScheme}.
 */
public class FiatShamirVerificationKey implements VerificationKey {
    @RepresentedArray(elementRestorer = @Represented)
    private Problem[] instance;

    public FiatShamirVerificationKey(Problem[] instance) {
        this.instance = instance;
    }

    public FiatShamirVerificationKey(Representation repr) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FiatShamirVerificationKey that = (FiatShamirVerificationKey) o;
        return Arrays.equals(getInstance(), that.getInstance());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getInstance());
    }

    public Problem[] getInstance() {
        return instance;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

}
