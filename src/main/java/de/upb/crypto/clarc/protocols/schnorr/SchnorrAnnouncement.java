package de.upb.crypto.clarc.protocols.schnorr;

import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SchnorrAnnouncement implements Announcement {
    @UniqueByteRepresented
    protected HashMap<String, Announcement> internalAnnouncements;
    @UniqueByteRepresented
    protected HashMap<String, SchnorrImage> randomImages;

    public SchnorrAnnouncement(Map<String, Announcement> internalAnnouncements, Map<String, SchnorrImage> randomImages) {
        this.internalAnnouncements = new HashMap<>(internalAnnouncements);
        this.randomImages = new HashMap<>(randomImages);
    }

    public Announcement getInternalAnnouncement(String statement) {
        return internalAnnouncements.get(statement);
    }

    public SchnorrImage getRandomImage(String statement) {
        return randomImages.get(statement);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        ObjectRepresentation announcementRepr = new ObjectRepresentation();
        ObjectRepresentation imageRepr = new ObjectRepresentation();

        internalAnnouncements.forEach((statement, internalAnnouncement) -> announcementRepr.put(statement, internalAnnouncement.getRepresentation()));
        randomImages.forEach((statement, image) -> imageRepr.put(statement, image.getRepresentation()));

        repr.put("announcements", announcementRepr);
        repr.put("images", imageRepr);

        return repr;
    }
}
