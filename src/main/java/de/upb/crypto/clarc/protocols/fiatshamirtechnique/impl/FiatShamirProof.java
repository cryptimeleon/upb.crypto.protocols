package de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl;

import de.upb.crypto.clarc.protocols.fiatshamirtechnique.FiatShamirHeuristic;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.Proof;
import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.clarc.protocols.arguments.sigma.Response;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A non-interactive proof that is produced by the {@link FiatShamirHeuristic}.
 * <p>
 * For effiency, we skipped to store the challenge, since it can be computed by applying (the correct) hash function
 * to {@link #announcementRepresentations} and {@link #auxData}.
 */
public class FiatShamirProof implements Proof {
    private Representation[] announcementRepresentations;

    /**
     * Additional data that is used to produce this proof. This data is used in the challenge generation. The
     * challenge itself can be restored by applying a hash function to {@link #announcementRepresentations} and this
     * data.
     */
    private ByteArrayImplementation[] auxData;

    private Representation[] responseRepresentations;

    public FiatShamirProof(Announcement[] announcements, ByteArrayImplementation[] auxData, Response[] responses) {
        announcementRepresentations = Arrays.stream(announcements)
                .map(Representable::getRepresentation).toArray(Representation[]::new);
        this.auxData = auxData;
        responseRepresentations = Arrays.stream(responses)
                .map(Representable::getRepresentation).toArray(Representation[]::new);
    }

    public FiatShamirProof(Representation representation) {
        ObjectRepresentation obj = representation.obj();
        announcementRepresentations = obj.get("announcementRepresentations").list().getArray();
        this.auxData = obj.get("auxData").list().stream()
                .map(ByteArrayImplementation::new)
                .toArray(ByteArrayImplementation[]::new);
        responseRepresentations = obj.get("responseRepresentations").list().getArray();
    }

    public Representation[] getAnnouncementRepresentations() {
        return announcementRepresentations;
    }

    public ByteArrayImplementation[] getAuxData() {
        return auxData;
    }

    public Representation[] getResponseRepresentations() {
        return responseRepresentations;
    }

    @Override
    public Representation getRepresentation() {
        final ObjectRepresentation representation = new ObjectRepresentation();
        representation.put("announcementRepresentations", new ListRepresentation(announcementRepresentations));
        List<Representation> reprOfAuxData = Arrays.stream(auxData)
                .map(ByteArrayImplementation::getRepresentation)
                .collect(Collectors.toList());
        representation.put("auxData", new ListRepresentation(reprOfAuxData));
        representation.put("responseRepresentations", new ListRepresentation(responseRepresentations));
        return representation;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || this.getClass() != obj.getClass()) {
            return false;
        }
        FiatShamirProof newObject = (FiatShamirProof) obj;

        if (announcementRepresentations == null) {
            return newObject.announcementRepresentations == null;
        } else if (!Arrays.equals(announcementRepresentations, newObject.announcementRepresentations)) {
            return false;
        }

        if (!Arrays.equals(auxData, newObject.auxData)) return false;

        if (responseRepresentations == null) {
            return newObject.responseRepresentations == null;
        } else if (!Arrays.equals(responseRepresentations, newObject.responseRepresentations)) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + ((announcementRepresentations == null) ?
                0 :
                Arrays.hashCode(announcementRepresentations));

        result = 31 * result + Arrays.hashCode(auxData);

        result = prime * result + ((responseRepresentations == null) ?
                0 :
                Arrays.hashCode(responseRepresentations));

        return result;
    }
}
