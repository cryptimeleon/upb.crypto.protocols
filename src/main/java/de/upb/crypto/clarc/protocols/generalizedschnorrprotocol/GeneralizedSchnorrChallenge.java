package de.upb.crypto.clarc.protocols.generalizedschnorrprotocol;

import de.upb.crypto.clarc.protocols.arguments.sigma.Challenge;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;

/**
 * A wrapper obejct for the challenge for GeneralizedSchnorrProtocol. It contains a single Zp element, that was
 * chosen uniformly at random
 */
public class GeneralizedSchnorrChallenge implements Challenge {

    private Zp.ZpElement challenge;


    public GeneralizedSchnorrChallenge(Zp.ZpElement challenge) {
        this.challenge = challenge;

    }

    public GeneralizedSchnorrChallenge(Representation representation, Zp zp) {
        this.challenge = zp.getElement(representation);
    }

    public Zp.ZpElement getChallenge() {
        return challenge;
    }

    /**
     * The representation of this object. Used for serialization
     * In this case the representation of the ZP element is returned.
     *
     * @return a Representation or null if the representedTypeName suffices to instantiate an equal object again
     * @see Representation
     */
    @Override
    public Representation getRepresentation() {
        return getChallenge().getRepresentation();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        GeneralizedSchnorrChallenge that = (GeneralizedSchnorrChallenge) o;

        return getChallenge() != null ? getChallenge().equals(that.getChallenge()) : that.getChallenge() == null;
    }

    @Override
    public int hashCode() {
        return getChallenge() != null ? getChallenge().hashCode() : 0;
    }


    @Override
    public String toString() {
        return this.challenge.toString();
    }
}
