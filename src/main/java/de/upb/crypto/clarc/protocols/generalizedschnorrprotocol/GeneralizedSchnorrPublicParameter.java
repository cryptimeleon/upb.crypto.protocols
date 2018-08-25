package de.upb.crypto.clarc.protocols.generalizedschnorrprotocol;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.math.serialization.BigIntegerRepresentation;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;

/**
 * Public parameters needed to set up a generalized schnorr protocol.
 * They contain:
 * - a list of m groups G_1,...,G_m,
 * - a m * n matrix of generators, g_{j,i} \in G_j
 * - a BigInteger n, that's the number of witnesses used in the protocol and the number of generators g_{j,i}, that
 * are given for each group.
 * - a BigInteger p, that's the size of groups |G_1| = ... = |G_m|
 */
public class GeneralizedSchnorrPublicParameter implements PublicParameters {

    private final BigInteger p;

    /**
     * Constructor for the {@link GeneralizedSchnorrPublicParameter}
     * They are needed to set up a generalized schnorr protocol.
     *
     * @param p a BigInteger p, that's the size of groups |G_1| = ... = |G_m|
     */
    public GeneralizedSchnorrPublicParameter(BigInteger p) {
        this.p = p;
    }

    public GeneralizedSchnorrPublicParameter(Representation representation) {
        final ObjectRepresentation objectRepresentation = representation.obj();

        this.p = objectRepresentation.get("p").bigInt().get();

    }

    /**
     * Creates "empty" {@link GeneralizedSchnorrPublicParameter} which can be used to construct an instance of an
     * {@link GeneralizedSchnorrProtocol} which can only be used to reconstruct its messages but can not actually
     * execute the protocol.
     * <p>
     * These type of protocols are needed during the non interactive proofs to ensure reconstruction is always possible.
     *
     * @param zp
     * @return {@link GeneralizedSchnorrPublicParameter} to create {@link GeneralizedSchnorrProtocol} only capable of
     * reconstructing its messages
     */
    public static GeneralizedSchnorrPublicParameter createEmptyParameters(Zp zp) {
        return new GeneralizedSchnorrPublicParameter(zp.size());
    }

    /**
     * The representation of this object. Used for serialization
     *
     * @return a Representation or null if the representedTypeName suffices to instantiate an equal object again
     * @see Representation
     */
    @Override
    public Representation getRepresentation() {
        ObjectRepresentation representation = new ObjectRepresentation();

        representation.put("p", new BigIntegerRepresentation(p));

        return representation;
    }

    public BigInteger getP() {
        return p;
    }


    @Override
    public boolean equals(Object o) {

        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        GeneralizedSchnorrPublicParameter that = (GeneralizedSchnorrPublicParameter) o;

        // Probably incorrect - comparing Object[] arrays with Arrays.equals
        return getP() != null ? getP().equals(that.getP()) : that.getP() == null;
    }

    @Override
    public int hashCode() {
        int result = 0;
        result = 31 * result + (getP() != null ? getP().hashCode() : 0);
        return result;
    }
}
