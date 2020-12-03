package de.upb.crypto.clarc.protocols.schnorr;

import de.upb.crypto.clarc.protocols.CommonInput;
import de.upb.crypto.clarc.protocols.arguments.sigma.*;
import de.upb.crypto.clarc.protocols.schnorr.stmts.api.SchnorrStatement;
import de.upb.crypto.clarc.protocols.schnorr.stmts.api.SchnorrVariable;
import de.upb.crypto.clarc.protocols.schnorr.stmts.api.SchnorrVariableValue;
import de.upb.crypto.math.interfaces.structures.GroupElement;

import java.util.HashMap;
import java.util.Set;

public class SchnorrSimulator implements SpecialHonestVerifierZkSimulator {
    protected SchnorrProtocol protocol;

    public SchnorrSimulator(SchnorrProtocol protocol) {
        this.protocol = protocol;
    }

    @Override
    public SigmaProtocolTranscript generateTranscript(CommonInput commonInput, Challenge challenge) {
        //Choose random response
        HashMap<SchnorrVariable, SchnorrVariableValue> response = new HashMap<>();
        for (SchnorrVariable variable : protocol.getEffectivePreimageSpace(commonInput))
            response.put(variable, variable.getRandomValue());

        SchnorrPreimage preimage = new SchnorrPreimage(response);

        //Compute corresponding announcement
        HashMap<String, Announcement> internalAnnouncements = new HashMap<>();
        HashMap<String, GroupElement> randomImages = new HashMap<>();
        for (SchnorrStatement stmt : protocol.statements) {
            Announcement internalAnnouncement = stmt.simulateInternalAnnouncement((SchnorrInput) commonInput);
            internalAnnouncements.put(stmt.getName(), internalAnnouncement);
            randomImages.put(stmt.getName(),
                    stmt.evaluateHomomorphism((SchnorrInput) commonInput, internalAnnouncement, preimage)
                    .op(stmt.getHomomorphismTarget((SchnorrInput) commonInput, internalAnnouncement)
                            .pow(((SchnorrChallenge) challenge).getChallenge().negate()))
            );
        }

        return new SigmaProtocolTranscript(new SchnorrAnnouncement(internalAnnouncements, randomImages), challenge, preimage);
    }
}
