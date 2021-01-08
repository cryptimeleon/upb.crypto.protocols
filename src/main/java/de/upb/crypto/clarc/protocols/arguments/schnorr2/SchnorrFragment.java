package de.upb.crypto.clarc.protocols.arguments.schnorr2;

import de.upb.crypto.clarc.protocols.SecretInput;
import de.upb.crypto.clarc.protocols.arguments.sigma.*;
import de.upb.crypto.math.expressions.bool.BooleanExpression;
import de.upb.crypto.math.serialization.Representation;

import java.util.Map;
import java.util.function.Function;

/**
 * Part of a Schnorr-style protocol, which may depend on variables (witnesses)
 * for which another protocol is in charge of ensuring extractability.
 * It is usually part of a larger composition of fragments that form a complete protocol.
 */
public interface SchnorrFragment {
    AnnouncementSecret generateAnnouncementSecret(SchnorrVariableAssignment outerWitnesses);

    Announcement generateAnnouncement(SchnorrVariableAssignment outerWitnesses, AnnouncementSecret announcementSecret, SchnorrVariableAssignment outerRandom);

    Response generateResponse(SchnorrVariableAssignment outerWitnesses, AnnouncementSecret announcementSecret, Challenge challenge);

    boolean checkTranscript(Announcement announcement, Challenge challenge, Response response, SchnorrVariableAssignment outerResponse);

    SigmaProtocolTranscript generateSimulatedTranscript(Challenge challenge, SchnorrVariableAssignment outerRandomResponse);

    Announcement recreateAnnouncement(Representation repr);
    Response recreateResponse(Announcement announcement, Representation repr);
}
