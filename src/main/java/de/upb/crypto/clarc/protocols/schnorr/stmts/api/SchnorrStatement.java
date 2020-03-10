package de.upb.crypto.clarc.protocols.schnorr.stmts.api;

import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.clarc.protocols.arguments.sigma.AnnouncementSecret;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrImage;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrInput;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrPreimage;
import de.upb.crypto.math.serialization.Representation;

import java.math.BigInteger;
import java.util.Collection;
import java.util.Map;

/**
 * A statement provable with the Schnorr protocol.
 * Generally, Schnorr allows proving knowledge of a preimage of a homomorphism.
 *
 * A statement may be something like "I know x such that h = g^x" (which is the basic Schnorr case)
 * or "I know x,y such that h = g^(x*y)" (which is not directly provable through Schnorr, but can be (computationally) proven by restating it as "I send you C = g^x * z^r, then I prove that I can open C to x and that I can open C^y to xy and that h = g^xy").
 *
 * Technically, a SchnorrStatement specifies the following:
 *
 * - A set of Schnorr witnesses. Witnesses may be external (example: x, y in the statements above), or internal (only used by this particular statement; example: r, xy above)
 * - An additional message ("internal announcement") sent alongside the usual announcement (example: commitment C above)
 * - How to evaluate the homomorphism (like x -> g^x in standard Schnorr) associated with this statement (the homomorphism may change depending on the internal announcement)
 * - What the homomorphism shall evaluate to for a valid witness.
 *
 * We note that implementing this interface obviously does not guarantee protocol security in any way.
 */
public abstract class SchnorrStatement {
    protected final String name;

    public SchnorrStatement(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public abstract Collection<SchnorrVariable> getWitnesses(SchnorrInput commonInput);
    public abstract SchnorrVariableValue getInternalWitnessValue(SchnorrInput commonInput, SchnorrInput secretInput, Announcement internalAnnouncement, AnnouncementSecret announcementSecret, SchnorrVariable variable);

    public abstract AnnouncementSecret generateInternalAnnouncementSecret(SchnorrInput commonInput, SchnorrInput secretInput);
    public abstract Announcement generateInternalAnnouncement(SchnorrInput commonInput, SchnorrInput secretInput, AnnouncementSecret announcementSecret);
    public abstract Announcement recreateInternalAnnouncement(SchnorrInput commonInput, Representation repr);
    public abstract Announcement simulateAnnouncement(SchnorrInput commonInput);

    public abstract SchnorrImage recreateImage(SchnorrInput commonInput, Representation repr);

    public abstract SchnorrImage getHomomorphismTarget(SchnorrInput commonInput, Announcement internalAnnouncement);
    public abstract SchnorrImage evaluateHomomorphism(SchnorrInput commonInput, Announcement internalAnnouncement, SchnorrPreimage preimage);

    /**
     * Returns an upper bound for the challenge (will be between 0 and whatever you return here).
     * Usually, this will be (some estimate of) the group order for this statement.
     *
     * @return a number s.t. the challenge space should be [0,thisNumber-1].
     */
    public abstract BigInteger getChallengeSpaceSize(SchnorrInput commonInput);
}
