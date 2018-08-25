package de.upb.crypto.clarc.protocols.generalizedschnorrprotocol;

import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;
import de.upb.crypto.math.serialization.annotations.RepresentedList;

/**
 * A wrapper object for the announcements for a GeneralizedSchnorrProtocol. It contains a group element.
 * This was computed in the following way: T_j = \prod_{i=1}^{n} (g_{j,i}^t_i) , where t_i &lt;- Z_p, p = |G_1| = ... =
 * |G_m|
 *
 * @implNote GeneralizedSchnorrAnnouncement is effectively {@link StandaloneRepresentable} and can therefore restore
 * itself via {@link GeneralizedSchnorrAnnouncement#GeneralizedSchnorrAnnouncement(Representation)}.
 * Nonetheless it <b>must not</b> implement {@link StandaloneRepresentable} directly, as that would break the
 * {@link RepresentedArray} and {@link RepresentedList} contract when used with the "elementRestorer" as intended.
 */
public class GeneralizedSchnorrAnnouncement implements Announcement {

    @Represented
    Group group;

    @UniqueByteRepresented
    @Represented(structure = "group", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement announcement;

    public GeneralizedSchnorrAnnouncement(GroupElement announcement) {
        this.announcement = announcement;
        this.group = announcement.getStructure();
    }

    public GeneralizedSchnorrAnnouncement(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public GroupElement getAnnouncement() {
        return announcement;
    }

    public void setAnnouncement(GroupElement announcement) {
        this.announcement = announcement;
        this.group = announcement.getStructure();
    }

    /**
     * The representation of this object. Used for serialization.
     * In this case, the representation of the stored group element is returned
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

        GeneralizedSchnorrAnnouncement that = (GeneralizedSchnorrAnnouncement) o;

        return getAnnouncement() != null ? getAnnouncement().equals(that.getAnnouncement()) : that.getAnnouncement()
                == null;
    }

    @Override
    public int hashCode() {
        return getAnnouncement() != null ? getAnnouncement().hashCode() : 0;
    }

    /**
     * Updates the ByteAccumulator with the bytes from this class. The input to the accumulators update function
     * should be an injective (with respect to a given domain) byte encoding of this object.
     *
     * @param accumulator the accumulator used
     */
    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

    @Override
    public String toString() {
        return this.announcement.toString();
    }

}
