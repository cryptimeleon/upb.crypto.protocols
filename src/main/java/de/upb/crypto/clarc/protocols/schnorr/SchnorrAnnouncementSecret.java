package de.upb.crypto.clarc.protocols.schnorr;

import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.clarc.protocols.arguments.sigma.AnnouncementSecret;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class SchnorrAnnouncementSecret implements AnnouncementSecret {
    protected SchnorrPreimage randomPreimage;
    protected HashMap<String, AnnouncementSecret> statementSecrets = new HashMap<>();
    protected HashMap<String, Announcement> statementInternalAnnouncements = new HashMap<>();

    public SchnorrAnnouncementSecret(SchnorrPreimage randomPreimage, Map<String, AnnouncementSecret> statementSecrets, Map<String, Announcement> statementInternalAnnouncements) {
        this.randomPreimage = randomPreimage;
        this.statementSecrets.putAll(statementSecrets);
        this.statementInternalAnnouncements.putAll(statementInternalAnnouncements);
    }

    public SchnorrPreimage getRandomPreimage() {
        return randomPreimage;
    }

    public AnnouncementSecret getStatementAnnouncementSecret(String statement) {
        return statementSecrets.get(statement);
    }

    public Announcement getInternalAnnouncement(String statement) {
        return statementInternalAnnouncements.get(statement);
    }

    public Map<String, Announcement> getInternalAnnouncements() {
        return Collections.unmodifiableMap(statementInternalAnnouncements);
    }
}
