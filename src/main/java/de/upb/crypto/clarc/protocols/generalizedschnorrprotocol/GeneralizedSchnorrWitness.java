package de.upb.crypto.clarc.protocols.generalizedschnorrprotocol;

import de.upb.crypto.clarc.protocols.parameters.Witness;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

/**
 * A witness for a generalized schnorr protocol. It contains a single
 * {@link de.upb.crypto.math.structures.zn.Zp.ZpElement} x, fulfilling the equation A=g^x and has a name
 */
public class GeneralizedSchnorrWitness implements Witness {


    @Represented(structure = "zp", recoveryMethod = Zp.ZpElement.RECOVERY_METHOD)
    private Zp.ZpElement x;
    @Represented
    private Zp zp;
    @Represented
    private String name;

    /**
     * Constructor for the generalized Schnorr witness, fulfilling A=g^x  for A is the value of LHS of
     * {@link GeneralizedSchnorrProblem} and g is  a generator.
     *
     * @param x    the witness
     * @param name the name of the witness, needs to be unique in the protocol instance!
     */
    public GeneralizedSchnorrWitness(Zp.ZpElement x, String name) {
        this.name = name;
        this.x = x;
        if (this.x == null) {
            throw new IllegalArgumentException("Cannot use a witness without a value, please use an empty witness " +
                    "instead");
        }
        this.zp = x.getStructure();
    }

    public GeneralizedSchnorrWitness(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public Zp.ZpElement getWitnessValue() {
        return x;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    /**
     * The representation of this object. Used for serialization
     *
     * @return a Representation or null if the representedTypeName suffices to instantiate an equal object again
     * @see Representation
     */
    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        GeneralizedSchnorrWitness that = (GeneralizedSchnorrWitness) o;

        if (x != null ? !x.equals(that.x) : that.x != null) return false;
        return name != null ? name.equals(that.name) : that.name == null;
    }

    @Override
    public int hashCode() {
        int result = x != null ? x.hashCode() : 0;
        result = 31 * result + (name != null ? name.hashCode() : 0);
        return result;
    }
}
