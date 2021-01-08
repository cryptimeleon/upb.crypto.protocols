package de.upb.crypto.clarc.protocols.arguments.sigma;

public interface AnnouncementSecret {
    static EmptyAnnouncementSecret EMPTY = new EmptyAnnouncementSecret();
    class EmptyAnnouncementSecret implements AnnouncementSecret {
        private EmptyAnnouncementSecret() {}
    }
}
