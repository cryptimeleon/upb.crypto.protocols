package de.upb.crypto.clarc.protocols.fiatshamirtechnique;

import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.arguments.NonInteractiveAoK;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirProof;
import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.clarc.protocols.arguments.sigma.Challenge;
import de.upb.crypto.clarc.protocols.arguments.sigma.Response;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.math.hash.impl.ByteArrayAccumulator;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.HashFunction;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Arrays;

/**
 * Implementation of the Fiat-Shamir heuristic as a non-interactive argument of knowledge ({@link NonInteractiveAoK}).
 * <p>
 * It is used to obtain a non-interactive version of some {@link InteractiveThreeWayAoK}. To this end, a prover
 * generates the protocol's {@link Challenge} herself by applying a {@link HashFunction} to the generated
 * {@link Announcement}.
 * Therefore, no interaction is needed anymore.
 * <p>
 * Note that, e.g. for a secure use of this scheme, it can be required that more data than only the announcement need
 * to get into the challenge generation.
 */
public class FiatShamirHeuristic implements NonInteractiveAoK {

    /**
     * The {@link InteractiveThreeWayAoK} that is made non-interactive.
     */
    @Represented
    private InteractiveThreeWayAoK protocol;

    /**
     * The {@link HashFunction} that is used to generate the challenge in {@link #prove(UniqueByteRepresentable...)}.
     */
    @Represented
    private HashFunction hashFunction;

    public FiatShamirHeuristic(InteractiveThreeWayAoK protocol, HashFunction hashFunction) {
        this.protocol = protocol;
        this.hashFunction = hashFunction;
    }

    public FiatShamirHeuristic(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    /**
     * <p>Generates a non-interactive proof of {@link #protocol}.</p>
     * <p>
     * Essentially, this method runs the prover part of {@link #protocol} meaning
     * {@link InteractiveThreeWayAoK#generateAnnouncements()} and
     * {@link InteractiveThreeWayAoK#generateResponses(Challenge)} for a
     * challenge computed herself using a hash of the computed announcement and given {@code auxData}.
     *
     * @param auxData possible additional data that influences the proof generation. Note that this parameter is
     *                optional.
     *                <p>
     *                This parameter can be used for various things, e.g. to ensure certain security requirements it
     *                might be necessary to generate the challenge depend on more than only the annoucement. An
     *                example could be a public key of the receiver of this proof.
     *                </p>
     * @return a {@link FiatShamirProof} for the given {@code auxData}
     */
    @Override
    public FiatShamirProof prove(UniqueByteRepresentable... auxData) {
        Announcement[] announcements = protocol.generateAnnouncements();
        Challenge challenge = generateChallenge(announcements, auxData);
        Response[] responses = protocol.generateResponses(challenge);

        ByteArrayImplementation[] auxDataBytes = Arrays.stream(auxData)
                .map(data -> new ByteArrayImplementation(data.getUniqueByteRepresentation()))
                .toArray(ByteArrayImplementation[]::new);
        return new FiatShamirProof(announcements, auxDataBytes, responses);
    }

    /**
     * @return generates a challenge by hashing the given {@code announcements} and {@code auxData} using
     * {@link #hashFunction}.
     */
    private Challenge generateChallenge(Announcement[] announcements, UniqueByteRepresentable... auxData) {
        return protocol.createChallengeFromByteArray(
                getHashForAnnouncementAndAuxData(announcements, auxData, hashFunction));
    }

    /**
     * Computes the hash of announcement and auxiliary information
     *
     * @param announcements first arguments of the hash function
     * @param auxData       second argument of the hash function
     * @param hashFunction  used to compute the hash
     * @return H(announcements, auxData)
     */
    public byte[] getHashForAnnouncementAndAuxData(Announcement[] announcements, UniqueByteRepresentable[] auxData,
                                                   HashFunction hashFunction) {
        ByteAccumulator accumulator = new ByteArrayAccumulator();

        Arrays.stream(announcements).forEach(announcement -> {
            accumulator.append(announcement.getUniqueByteRepresentation());
            accumulator.appendSeperator();
        });

        Arrays.stream(auxData).forEach(data -> {
            accumulator.append(data.getUniqueByteRepresentation());
            accumulator.appendSeperator();
        });

        return hashFunction.hash(accumulator.extractBytes());
    }

    @Override
    public boolean verify(Proof proof) {
        if (!(proof instanceof FiatShamirProof)) {
            throw new IllegalArgumentException("Wrong type of proof for this scheme!");
        }
        FiatShamirProof fiatShamirTranscript = (FiatShamirProof) proof;

        final Announcement[] announcements;
        final Response[] responses;
        final Challenge challenge;
        // This should eventually be changed, but if the recreation fails we get errors elsewhere since
        // it is set to null in that case
        try {
            announcements = Arrays.stream(fiatShamirTranscript.getAnnouncementRepresentations())
                    .map(repr -> protocol.recreateAnnouncement(repr))
                    .toArray(Announcement[]::new);
            responses = Arrays.stream(fiatShamirTranscript.getResponseRepresentations())
                    .map(repr -> protocol.recreateResponse(repr))
                    .toArray(Response[]::new);
            challenge = generateChallenge(announcements, fiatShamirTranscript.getAuxData());
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
        return protocol.verify(announcements, challenge, responses);
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public InteractiveThreeWayAoK getProtocol() {
        return protocol;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }

        FiatShamirHeuristic that = (FiatShamirHeuristic) obj;
        if (!this.protocol.equals(that.protocol)) {
            return false;
        }
        return this.hashFunction.equals(that.hashFunction);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((protocol == null) ? 0 : protocol.hashCode());
        result = prime * result + ((hashFunction == null) ? 0 : hashFunction.hashCode());
        return result;
    }
}