package de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl;

import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.FiatShamirSignatureScheme;
import de.upb.crypto.clarc.protocols.parameters.Problem;
import de.upb.crypto.craco.interfaces.signature.Signature;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;

import java.util.Arrays;
import java.util.Objects;

/**
 * A {@link Signature} type for the {@link FiatShamirSignatureScheme}.
 */
public class FiatShamirSignature implements Signature {
    /**
     * A problem instance {@link #proof} is generated from. It is needed to recreate the
     * {@link InteractiveThreeWayAoK} in {@link FiatShamirSignatureScheme#getSignature(Representation)}.
     */
    @RepresentedArray(elementRestorer = @Represented)
    private Problem[] instance;
    /**
     * {@link FiatShamirProof} representing the actual signature
     */
    @Represented
    private FiatShamirProof proof;

    public FiatShamirSignature(Problem[] instance, FiatShamirProof proof) {
        this.instance = instance;
        this.proof = proof;
    }

    public FiatShamirSignature(Representation repr) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);

    }

    public FiatShamirProof getProof() {
        return proof;
    }

    public Problem[] getInstance() {
        return instance;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FiatShamirSignature that = (FiatShamirSignature) o;
        return Arrays.equals(getInstance(), that.getInstance()) &&
                Objects.equals(getProof(), that.getProof());
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(getProof());
        result = 31 * result + Arrays.hashCode(getInstance());
        return result;
    }
}
