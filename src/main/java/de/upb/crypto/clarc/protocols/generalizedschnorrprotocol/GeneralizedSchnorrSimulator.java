package de.upb.crypto.clarc.protocols.generalizedschnorrprotocol;

import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.simulator.SigmaProtocolTranscript;
import de.upb.crypto.clarc.protocols.simulator.SpecialHonestVerifierSimulator;
import de.upb.crypto.clarc.protocols.simulator.Transcript;
import de.upb.crypto.math.interfaces.structures.FutureGroupElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;

/**
 * Special honest verifier simulator for a generalized Schnorr protocol.
 * Given a challenge, the responses are chosen uniformly at random from Z_p, p = |G_1| = ... = |G_m|
 * Thereby, the randomness used in the announcement is fixed, since witness x_i and challenge c are fixed.
 * Afterwards, T_j = A_j ^c \op \prod_{i} g_{j,i} ^ {s_i} is calculated.
 * Finally the transcript is returned.
 */
public class GeneralizedSchnorrSimulator extends SpecialHonestVerifierSimulator {
    public GeneralizedSchnorrSimulator(GeneralizedSchnorrProtocol protocolInstance) {
        super(protocolInstance);
    }

    /**
     * Given a challenge, the responses are chosen uniformly at random from Z_p, p = |G_1| = ... = |G_m|
     * Thereby, the randomness used in the announcement is fixed, since witness x_i and challenge c are fixed.
     * Afterwards, T_j = A_j ^c \op \prod_{i} g_{j,i} ^ {s_i} is calculated.
     * Finally the transcript is returned.
     *
     * @param challenge used to generate the transcript
     * @return an accepting transcript using the given challenge
     */
    @Override
    public Transcript simulate(Challenge challenge) {
        if (!(this.protocolInstance instanceof GeneralizedSchnorrProtocol)) {
            throw new IllegalArgumentException("The given protocol is not valid");
        }
        if (!(challenge instanceof GeneralizedSchnorrChallenge)) {
            throw new IllegalArgumentException("The given challenge is not valid");
        }
        GeneralizedSchnorrProtocol protocol = (GeneralizedSchnorrProtocol) this.protocolInstance;
        GeneralizedSchnorrChallenge generalizedSchnorrChallenge = (GeneralizedSchnorrChallenge) challenge;
        GeneralizedSchnorrPublicParameter publicParameter = (GeneralizedSchnorrPublicParameter) protocol.getPublicParameters();

        GeneralizedSchnorrProblem[] problem =
                Arrays.stream(protocol.getProblems()).map(p -> (GeneralizedSchnorrProblem) p)
                        .toArray(GeneralizedSchnorrProblem[]::new);


        //Generate a response for each variable
        HashSet<String> variables = protocol.getVariables();
        Zp zp = new Zp(publicParameter.getP());
        GeneralizedSchnorrResponse[] responses = new GeneralizedSchnorrResponse[variables.size()];
        HashMap<String, Zp.ZpElement> s_iMap = new HashMap<>();
        int i = 0;
        for (String var : variables) {
            Zp.ZpElement rnd = zp.getUniformlyRandomElement();
            responses[i++] = new GeneralizedSchnorrResponse(var, rnd);
            s_iMap.put(var, rnd);
        }

        //Generate corresponding announcements T_j
        FutureGroupElement[] futureAnnouncements = protocol.recomputeTjForVerification(generalizedSchnorrChallenge.getChallenge(),
                GeneralizedSchnorrProtocol.mapToFacts(s_iMap));

        //Collect results
        GeneralizedSchnorrAnnouncement[] announcements = new GeneralizedSchnorrAnnouncement[problem.length];
        for (int j = 0; j < problem.length; j++)
            announcements[j] = new GeneralizedSchnorrAnnouncement(futureAnnouncements[j].get());

        return new SigmaProtocolTranscript(announcements, generalizedSchnorrChallenge, responses, protocol);
    }
}
