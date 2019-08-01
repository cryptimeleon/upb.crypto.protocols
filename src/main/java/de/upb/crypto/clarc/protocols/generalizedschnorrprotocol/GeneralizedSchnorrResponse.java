package de.upb.crypto.clarc.protocols.generalizedschnorrprotocol;

import de.upb.crypto.clarc.protocols.arguments.sigma.Response;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StringRepresentation;
import de.upb.crypto.math.structures.zn.Zp;

/**
 * Response for a generalized schnorr protocol.
 * A response s_i contains a single {@link de.upb.crypto.math.structures.zn.Zp.ZpElement} and is computed as follows:
 * s_i = x_i * c +t_i, where x_i is the witnesses, c the challenge and t_i the randomnesses used int the
 * announcement-generation
 */
public class GeneralizedSchnorrResponse implements Response {

    private String variableName;
    private Zp.ZpElement response;

    /**
     * Constructor for a generalized schnorr response
     *
     * @param variableName the corresponding Variable name this response is associated with
     * @param response     the {@link de.upb.crypto.math.structures.zn.Zp.ZpElement}  s_i, p =|G_1| = ... = |G_m|
     */
    public GeneralizedSchnorrResponse(String variableName, Zp.ZpElement response) {
        this.variableName = variableName;
        this.response = response;
    }

    public Zp.ZpElement getResponse() {
        return response;
    }

    public String getVariableName() {
        return variableName;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("variableName", new StringRepresentation(variableName));
        repr.put("value", response.getRepresentation());

        return repr;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        GeneralizedSchnorrResponse that = (GeneralizedSchnorrResponse) o;

        return getResponse() != null ? getResponse().equals(that.getResponse()) : that.getResponse() == null;
    }

    @Override
    public int hashCode() {
        return getResponse() != null ? getResponse().hashCode() : 0;
    }

    @Override
    public String toString() {
        return this.response.toString();
    }


}
