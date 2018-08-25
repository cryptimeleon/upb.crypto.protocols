package de.upb.crypto.clarc.protocols.protocolfactory;

import de.upb.crypto.clarc.protocols.expressions.comparison.ArithComparisonExpression;
import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProblem;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrPublicParameter;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrWitnessNew;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class GeneralizedSchnorrProtocolFactory {

    private final ArithComparisonExpression[] listOfProblems;
    private final Zp zp;

    /**
     * Generates a generalized Schnorr protocol for an CS-notation.
     *
     * @param listOfProblems List of Gen schnorr problems. They need to use all witnesses defined in the cs-notation
     * @param zp             the group, where all witnesses are from
     */
    public GeneralizedSchnorrProtocolFactory(ArithComparisonExpression[] listOfProblems, Zp zp) {
        this.listOfProblems = listOfProblems;
        this.zp = zp;
    }

    /**
     * Creates a instance of the Generalized Schnorr protocol, described by the problem.
     *
     * @return a generalized Schnorr protocol for a verifier, meaning that only 2 algorithms (challenge, verify) are
     * applicable
     */
    public GeneralizedSchnorrProtocol createVerifierGeneralizedSchnorrProtocol() {
        return this.createProtocol(new HashMap<>());
    }

    /**
     * Creates a instance of the Generalized Schnorr protocol, described by the problem.
     * Additionally, the prover needs to hand over a mapping of variable-names to concrete values of the witnesses.
     *
     * @param witnessMap mapping of witness names (String) to the corresponding values of the witnesses
     * @return a generalized Schnorr protocol for a prover, meaning that all 4 algorithms (announcement, challenge,
     * response, verify) are usable
     */
    public GeneralizedSchnorrProtocol createProverGeneralizedSchnorrProtocol(Map<String, Zp.ZpElement> witnessMap) {
        return this.createProtocol(witnessMap);
    }


    private GeneralizedSchnorrProtocol createProtocol(Map<String, Zp.ZpElement> witnessMap) {
        //Check if the problems that are given are valid w.r.t. the generalized Schnorr protocol
        if (Arrays.stream(listOfProblems).anyMatch(expr -> !(expr instanceof GroupElementEqualityExpression))) {
            throw new IllegalArgumentException("The given list of Problems contains an element that is not a " +
                    "GroupElementEqualityExpression");
        }
        GeneralizedSchnorrProblem[] problem = Arrays.stream(listOfProblems).map(p -> new GeneralizedSchnorrProblem(
                (GroupElementEqualityExpression) p)).toArray(GeneralizedSchnorrProblem[]::new);
        if (Arrays.stream(problem).anyMatch(GeneralizedSchnorrProtocol::isInvalidProblem)) {
            throw new IllegalArgumentException("The given list of Problems does contains an invalid equation");
        }

        GeneralizedSchnorrPublicParameter publicParameter = new GeneralizedSchnorrPublicParameter(zp.size());

        return new GeneralizedSchnorrProtocol(problem, new GeneralizedSchnorrWitnessNew(witnessMap), publicParameter);
    }
}
