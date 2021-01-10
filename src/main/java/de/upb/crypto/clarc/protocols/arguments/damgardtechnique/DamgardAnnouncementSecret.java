package de.upb.crypto.clarc.protocols.arguments.damgardtechnique;

import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.clarc.protocols.arguments.sigma.AnnouncementSecret;
import de.upb.crypto.craco.commitment.interfaces.CommitmentPair;

public class DamgardAnnouncementSecret implements AnnouncementSecret {
    final AnnouncementSecret innerAnnouncementSecret;
    final Announcement innerAnnouncement;
    final CommitmentPair commitment;

    public DamgardAnnouncementSecret(AnnouncementSecret innerAnnouncementSecret, Announcement innerAnnouncement, CommitmentPair commitment) {
        this.innerAnnouncementSecret = innerAnnouncementSecret;
        this.innerAnnouncement = innerAnnouncement;
        this.commitment = commitment;
    }
}
