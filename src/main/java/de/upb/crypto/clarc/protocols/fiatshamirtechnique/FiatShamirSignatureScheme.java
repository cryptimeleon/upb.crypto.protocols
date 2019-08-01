package de.upb.crypto.clarc.protocols.fiatshamirtechnique;

import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirProof;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirSignature;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirSigningKey;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirVerificationKey;
import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.clarc.protocols.parameters.EmptyWitness;
import de.upb.crypto.clarc.protocols.parameters.Problem;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.craco.interfaces.signature.Signature;
import de.upb.crypto.craco.interfaces.signature.SignatureScheme;
import de.upb.crypto.craco.interfaces.signature.SigningKey;
import de.upb.crypto.craco.interfaces.signature.VerificationKey;
import de.upb.crypto.math.interfaces.hash.HashFunction;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Arrays;
import java.util.Objects;

/**
 * Implementation of the Fiat-Shamir heuristic as a signature scheme ({@link SignatureScheme}).
 * <p>
 * Internally it works like the {@link FiatShamirHeuristic} except that for this implementation a {@link PlainText}
 * message is given for the challenge generation in addtion to the annoucement.
 */
public class FiatShamirSignatureScheme implements SignatureScheme {
    /**
     * Function that provides a {@link InteractiveThreeWayAoK} instance given a {@link Problem} and a {@link Witness}.
     */
    @Represented
    private ProtocolProvider protocolProvider;

    /**
     * The {@link HashFunction} used to internally generate the challenge.
     */
    @Represented
    private HashFunction hash;

    public FiatShamirSignatureScheme(ProtocolProvider protocolProvider, HashFunction hash) {
        this.protocolProvider = protocolProvider;
        this.hash = hash;
    }

    public FiatShamirSignatureScheme(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Internally, it setups up a {@link InteractiveThreeWayAoK} instance using {@code signingKey} and generates a
     * {@link FiatShamirProof} using the {@link FiatShamirHeuristic}.
     *
     * @param plainText  message to be signed
     * @param signingKey private key the message is to be signed under. Should be an instance of
     *                   {@link FiatShamirSigningKey}
     * @return a {@link FiatShamirSignature} of {@code plaintext} under {@code signing key}
     */
    @Override
    public FiatShamirSignature sign(PlainText plainText, SigningKey signingKey) {
        if (!(signingKey instanceof FiatShamirSigningKey)) {
            throw new IllegalArgumentException("Not a valid signing key for this scheme!");
        }

        FiatShamirSigningKey sk = (FiatShamirSigningKey) signingKey;
        InteractiveThreeWayAoK protocol = protocolProvider.getProtocolInstance(sk.getInstance(), sk.getWitness());

        FiatShamirHeuristic fiatShamirHeuristic = new FiatShamirHeuristic(protocol, hash);
        FiatShamirProof proof = fiatShamirHeuristic.prove(plainText);

        return new FiatShamirSignature(sk.getInstance(), proof);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Internally, it setups up a {@link InteractiveThreeWayAoK} instance using {@code verificationKey} and verifies the
     * {@link FiatShamirProof} contained in {@code signature}.
     *
     * @param plainText       a plaintext to verify {@code signature} with
     * @param signature       a {@link FiatShamirSignature} to be verified
     * @param verificationKey a {@link FiatShamirVerificationKey}
     * @return true iff the given {@code signature} is valid for {@code plainText} under {@code verificationKey}.
     */
    @Override
    public Boolean verify(PlainText plainText, Signature signature, VerificationKey verificationKey) {
        if (!(verificationKey instanceof FiatShamirVerificationKey)) {
            throw new IllegalArgumentException("Not a valid verification key for this scheme!");
        }
        if (!(signature instanceof FiatShamirSignature)) {
            throw new IllegalArgumentException("Not a valid signature for this scheme!");
        }

        FiatShamirVerificationKey pk = (FiatShamirVerificationKey) verificationKey;
        FiatShamirSignature fiatShamirSignature = (FiatShamirSignature) signature;

        //Recreate protocol from public key
        InteractiveThreeWayAoK protocol =
                protocolProvider.getProtocolInstance(pk.getInstance(), new Witness[]{new EmptyWitness("")});
        FiatShamirHeuristic fiatShamirHeuristic = new FiatShamirHeuristic(protocol, hash);

        // Recreate announcements
        final FiatShamirProof proof = fiatShamirSignature.getProof();
        Announcement[] announcementsFromSignature =
                Arrays.stream(proof.getAnnouncementRepresentations())
                        .map(protocol::recreateAnnouncement)
                        .toArray(Announcement[]::new);

        // Compute H(Announcement, Message) and recompute c = H(Announcement, auxData)
        byte[] recomputedHash = fiatShamirHeuristic.getHashForAnnouncementAndAuxData(announcementsFromSignature,
                new UniqueByteRepresentable[]{plainText}, hash);
        byte[] originalHash = fiatShamirHeuristic
                .getHashForAnnouncementAndAuxData(announcementsFromSignature, proof.getAuxData(), hash);
        boolean plainTextIsValid = Arrays.equals(recomputedHash, originalHash);

        return plainTextIsValid && fiatShamirHeuristic.verify(proof);
    }

    @Override
    public PlainText getPlainText(Representation representation) {
        return new MessageBlock(representation, RingElementPlainText::new);

    }

    @Override
    public FiatShamirSignature getSignature(Representation representation) {
        return new FiatShamirSignature(representation);
    }

    @Override
    public FiatShamirSigningKey getSigningKey(Representation representation) {
        return new FiatShamirSigningKey(representation);
    }

    @Override
    public FiatShamirVerificationKey getVerificationKey(Representation representation) {
        return new FiatShamirVerificationKey(representation);
    }

    @Override
    public ByteArrayImplementation mapToPlaintext(byte[] bytes, SigningKey signingKey) {
        return new ByteArrayImplementation(bytes);
    }

    @Override
    public ByteArrayImplementation mapToPlaintext(byte[] bytes, VerificationKey verificationKey) {
        return new ByteArrayImplementation(bytes);
    }

    @Override
    public int getMaxNumberOfBytesForMapToPlaintext() {
        return Integer.MAX_VALUE; //plaintext can be any byte string (usage with hash function)
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FiatShamirSignatureScheme that = (FiatShamirSignatureScheme) o;
        return Objects.equals(protocolProvider, that.protocolProvider) &&
                Objects.equals(hash, that.hash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(protocolProvider, hash);
    }
}
