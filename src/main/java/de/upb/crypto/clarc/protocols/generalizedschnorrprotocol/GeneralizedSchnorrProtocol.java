package de.upb.crypto.clarc.protocols.generalizedschnorrprotocol;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.expressions.SimpleZnElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.SuperGroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.ZnElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.arith.Variable;
import de.upb.crypto.clarc.protocols.parameters.*;
import de.upb.crypto.clarc.protocols.simulator.SpecialHonestVerifierSimulator;
import de.upb.crypto.math.interfaces.structures.FutureGroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.*;
import java.util.logging.Logger;

/**
 * A generalized Schnorr protocol is used for a zero knowledge proof of knowledge of a list of ZpElements.
 * These elements, called witnesses, fulfill the equation A_j  = \prod_{i=1}_{n} (g_{j,i}^x_i )
 * for 1 &lt;= j &lt;= m, A_j, g_j,i \in G_j for all 1 &lt;= i &lt;= n, 1 &lt;= j &lt;= m
 */
public class GeneralizedSchnorrProtocol extends SigmaProtocol implements StandaloneRepresentable {

    /**
     * Map from variables in the equations to concrete values
     */
    private GeneralizedSchnorrWitnessNew witnessMapping;

    /**
     * Map from variables in the equations to random blinding values
     */
    private Map<String, Zp.ZpElement> randomValues;

    @Represented
    private Zp zp;
    @Represented
    private GeneralizedSchnorrPublicParameter pp;
    private final static Logger LOGGER = Logger.getLogger(GeneralizedSchnorrProtocol.class.getName());

    /**
     * true if isFulfilled(), false if !isFulfilled(), null if fulfillment was not yet computed.
     */
    private Boolean isFulfilled = null;

    /**
     * Constructor for a generalized Schnorr Protocol, proving knowledge for the relation A_j = g_j,i ^ x_i
     *
     * @param problems         A list of problems, represented by a list of equations where the LHS of the equation
     *                         contains the fixed Values A_j. Additionally the parameters
     * @param witness
     * @param publicParameters
     */
    public GeneralizedSchnorrProtocol(Problem[] problems, GeneralizedSchnorrWitnessNew witness,
                                      GeneralizedSchnorrPublicParameter publicParameters) {
        super(problems, new Witness[]{witness}, publicParameters);
        this.witnessMapping = witness;
        this.pp = publicParameters;
        this.zp = new Zp(pp.getP());
    }

    public GeneralizedSchnorrProtocol(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    /**
     * The representation of this object. Used for serialization
     *
     * @return a Representation or null if the representedTypeName suffices to instantiate an equal object again
     * @see Representation
     */
    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }


    @Override
    public GeneralizedSchnorrProtocol setWitnesses(List<Witness> witnesses) {
        throw new RuntimeException("Not implemented.");
        /*this.isFulfilled = null;
        if (witnesses.stream().anyMatch(w -> !(w instanceof GeneralizedSchnorrWitness))) {
            throw new IllegalArgumentException("The given witnesses does contain a witness that is not a " +
                    "GeneralizedSchnorrWitness");
        }
        for (Witness newWitness : witnesses) {
            for (int i = 0; i < this.witnesses.length; i++) {

                Witness currentWitness = this.witnesses[i];
                if (newWitness.getName().equals(currentWitness.getName())) {
                    this.witnesses[i] = newWitness;
                    break;
                }
            }
        }
        return this;*/
    }

    @Override
    public Challenge createChallengeFromByteArray(byte[] integer) {
        return new GeneralizedSchnorrChallenge(zp.createZnElement(new BigInteger(integer)));
    }

    /**
     * checks if the sigma protocol is fulfilled using the witnesses stored inside the protocol
     *
     * @return true, if the witnesses fulfill the problem equations, false otherwise
     */
    @Override
    public boolean isFulfilled() {
        if (this.isFulfilled != null)
            return this.isFulfilled;

        if (witnessMapping == null || witnessMapping.getMap().containsValue(null)) {
            return this.isFulfilled = false;
        }

        //Check if set of witnesses is complete
        if (witnessIsMissingVariables())
            return this.isFulfilled = false;

        //Compute RHS * LHS^(-1)
        FutureGroupElement[] results = new FutureGroupElement[problems.length];
        for (int j = 0; j < problems.length; j++) {
            GeneralizedSchnorrProblem gsProb = (GeneralizedSchnorrProblem) problems[j];
            results[j] = gsProb.getRHS().resultAsEfficientExpression(new SuperGroupElementPolicyFacts(), witnessMapping)
                    .op(gsProb.getValueOfA().inv()).evaluateConcurrent();
        }

        //Make sure it returns 1
        for (int j = 0; j < problems.length; j++) {
            if (!results[j].get().isNeutralElement())
                return this.isFulfilled = false;
        }
        return this.isFulfilled = true;
    }

    /**
     * Generates the announcements, choosing randomness internally.
     * T_j = \prod {i=1}^{n} g_{j,i}^t_i
     * for more information see super class
     *
     * @return an array of m announcements, where m is the number of Problems and number of groups used
     */
    @Override
    public Announcement[] generateAnnouncements() {
        Zp zp = new Zp(this.pp.getP());
       /*if (Arrays.stream(super.witnesses).anyMatch(w -> !(w instanceof GeneralizedSchnorrWitness))) {
            throw new IllegalArgumentException("The given Witness is not an instance of a generalized Schnorr " +
                    "witness");
        }*/
        if (Arrays.stream(super.problems).anyMatch(p -> !(p instanceof GeneralizedSchnorrProblem))) {
            throw new IllegalArgumentException("The given Problem is not an instance of a generalized Schnorr " +
                    "problem");
        }

        //Creates an array of size m = #Problems
        GeneralizedSchnorrProblem[] gsProblem = Arrays.stream(super.problems).map(p -> (GeneralizedSchnorrProblem) p)
                .toArray(GeneralizedSchnorrProblem[]::new);
        //Collect variables
        HashSet<String> variables = getVariables();

        //Choose random values to blind variables with
        this.randomValues = new HashMap<>();
        for (String var : variables) {
            this.randomValues.put(var, zp.getUniformlyRandomElement());
        }

        //Wrap random values into Facts for convenient calculation
        ZnElementPolicyFacts facts = mapToFacts(this.randomValues);

        //Calculate the T_j
        FutureGroupElement[] futureAnnouncements = new FutureGroupElement[gsProblem.length];
        for (int j = 0; j < gsProblem.length; j++) {
            futureAnnouncements[j] = gsProblem[j].getRHS() //compute using random assignments for the variables
                    .resultAsEfficientExpression(new SuperGroupElementPolicyFacts(), facts)
                    .evaluateConcurrent();
        }

        //Collect results
        GeneralizedSchnorrAnnouncement[] gsAnnouncements = new GeneralizedSchnorrAnnouncement[gsProblem.length];
        for (int j = 0; j < gsProblem.length; j++) {
            gsAnnouncements[j] = new GeneralizedSchnorrAnnouncement(futureAnnouncements[j].get());
        }

        return gsAnnouncements;
    }

    protected static ZnElementPolicyFacts mapToFacts(Map<String, Zp.ZpElement> values) {
        HashMap<String, Zp.ZpElement> factsFormat = new HashMap<>();
        values.forEach(factsFormat::put);
        return new SimpleZnElementPolicyFacts(factsFormat);
    }

    /**
     * Chooses a challenge from Z_p, p = |G_1| = ... = |G_m|
     *
     * @return a random element from Zp
     */
    @Override
    public Challenge chooseChallenge() {
        return new GeneralizedSchnorrChallenge(new Zp((this.pp.getP()))
                .getUniformlyRandomElement());
    }

    /**
     * Computes the responses for the protocol, s_i = x_i * c + t_i, where x_i is the i-th witness, c the challenge
     * and t_i the i-th random element chosen in the generation of the announcements.
     *
     * @param challenge the challenge chosen by the verifier
     * @return an array of n responses, one for each witness.
     */
    public GeneralizedSchnorrResponse[] generateResponses(Challenge challenge) {
        if (randomValues == null) {
            throw new IllegalArgumentException("Randomness must be provided.");
        }
        if (challenge == null || !(challenge instanceof GeneralizedSchnorrChallenge)) {
            throw new IllegalArgumentException("The given challenge is invalid.");
        }
        if (witnessMapping == null) {
            throw new IllegalArgumentException("There are no witnesses given, thus the response can not be " +
                    "generated.");
        }
        if (witnessIsMissingVariables())
            throw new IllegalArgumentException("The given witness is incomplete.");

        GeneralizedSchnorrChallenge genSchnorrChallenge = (GeneralizedSchnorrChallenge) challenge;
        HashSet<String> variables = getVariables();
        GeneralizedSchnorrResponse[] response = new GeneralizedSchnorrResponse[variables.size()];
        int i = 0;
        for (String var : variables) {
            response[i++] = new GeneralizedSchnorrResponse(var,
                    genSchnorrChallenge.getChallenge().mul(witnessMapping.getWitnessValue(var)).add(randomValues.get(var)));
        }

        randomValues = null; //avoid ever answering two challenges with the same randomness
        return response;
    }

    /**
     * Verification of announcement, challenge and response.
     * The verification is 'true' iff for all 1 &lt;= j &lt;= m it holds that:
     * \prod_{i} (g_j,i ^s_i) = A_j ^c * T_j
     *
     * @param announcements the announcements obtained by the prover
     * @param challenge     the challenge chosen by verifier and given to the prover
     * @param responses     the responses generated by the prover
     * @return true, iff  for all 1 &lt;= j &lt;= m it holds that: prod_{i} (g_j,i ^s_i) = A_j ^c * T_j, else false.
     */
    @Override
    public boolean verify(Announcement[] announcements, Challenge challenge, Response[] responses) {

        if (announcements == null || Arrays.stream(announcements)
                .anyMatch(a -> !(a instanceof GeneralizedSchnorrAnnouncement))) {
            throw new IllegalArgumentException("the given announcements are not valid to call this verify method");
        }

        if (challenge == null || !(challenge instanceof GeneralizedSchnorrChallenge)) {
            throw new IllegalArgumentException("the given challenge is not valid to call this verify method");
        }

        if (responses == null || Arrays.stream(responses).anyMatch(r -> !(r instanceof GeneralizedSchnorrResponse))) {
            throw new IllegalArgumentException("the given responses are not valid to call this verify method");
        }

        if (problems.length != announcements.length) {
            throw new IllegalArgumentException("The number of given announcements is incorrect!");
        }

        //Organize responses
        HashMap<String, Zp.ZpElement> responseMapTmp = new HashMap<>();
        for (Response response : responses) {
            responseMapTmp.put(((GeneralizedSchnorrResponse) response).getVariableName(),
                    ((GeneralizedSchnorrResponse) response).getResponse());
        }
        HashSet<String> variables = getVariables();
        HashMap<String, Zp.ZpElement> responseMap = new HashMap<>();
        variables.forEach(var -> responseMap.put(var, responseMapTmp.get(var)));
        ZnElementPolicyFacts s_iFacts = mapToFacts(responseMap);

        //Prepare challenge
        Zp.ZpElement gsChallenge = ((GeneralizedSchnorrChallenge) challenge).getChallenge();

        //Calculate the first part of the verification equations
        FutureGroupElement[] futureValues = recomputeTjForVerification(gsChallenge, s_iFacts);

        //Do equation check futureValues[j] = T_j
        for (int j = 0; j < problems.length; j++) {
            if (!futureValues[j].get().equals(((GeneralizedSchnorrAnnouncement) announcements[j]).getAnnouncement()))
                return false;
        }

        //If all equations are correct (not faulty), true is returned!
        return true;
    }

    /**
     * Computes \prod g_(j,i)^s_i * A_j^(-c)
     *
     * @param challenge
     * @param s_iFacts
     * @return
     */
    protected FutureGroupElement[] recomputeTjForVerification(Zp.ZpElement challenge, ZnElementPolicyFacts s_iFacts) {
        FutureGroupElement[] futureValues = new FutureGroupElement[problems.length];
        for (int j = 0; j < problems.length; j++) {
            GeneralizedSchnorrProblem prob = (GeneralizedSchnorrProblem) problems[j];
            futureValues[j] = prob.getRHS().resultAsEfficientExpression(new SuperGroupElementPolicyFacts(), s_iFacts)
                    .op(prob.getValueOfA().pow(challenge).inv()).evaluateConcurrent();
        }

        return futureValues;
    }

    /**
     * This method restores the serialized array of announcements
     *
     * @param representation of the announcement array
     * @return the restored announcement array
     */
    @Override
    public GeneralizedSchnorrAnnouncement recreateAnnouncement(Representation representation) {
        return new GeneralizedSchnorrAnnouncement(representation);
    }

    /**
     * This method restores the serialized array of challenge
     *
     * @param representation of the challenge
     * @return the restored challenge
     */
    @Override
    public GeneralizedSchnorrChallenge recreateChallenge(Representation representation) {
        return new GeneralizedSchnorrChallenge(zp.getElement(representation));
    }

    /**
     * This method restores the serialized array of responses
     *
     * @param representation of the announcement array
     * @return the restored responses array
     */
    @Override
    public GeneralizedSchnorrResponse recreateResponse(Representation representation) {
        return recreateResponse(representation, this.zp);
    }

    /**
     * Checks if the LHS is a fixed value. Therefore, it may either be a constant or a variable with fixed value.
     * Moreover, it is checked if the RHS is a product-expression of different Power-expressions
     * A valid Problem has the following form : A = \prod_{i} a_i ^ w_i  , where A is fixed, a_i can be computed and
     * w_i is the witness
     *
     * @param problem problem to be checked
     * @return true, if the problem is valid
     */
    public static boolean isInvalidProblem(Problem problem) {
        if (!(problem instanceof GeneralizedSchnorrProblem)) {
            return true;
        }
        return false; //form is checked in constructor of GeneralizedSchnorrProblem
    }

    /**
     * Computes the set of variables in the problem expressions.
     * This corresponds to witnesses of the Schnorr protocol
     *
     * @return
     */
    public HashSet<String> getVariables() {
        HashSet<Variable> variables = new HashSet<>();
        for (Problem problem : problems)
            ((GeneralizedSchnorrProblem) problem).getVariables(variables);

        HashSet<String> result = new HashSet<>();
        for (Variable var : variables)
            result.add(var.getName());
        return result;
    }

    /**
     * Returns true iff the witness is incomplete, i.e. there is some
     * variable in the equation that does not get a value.
     */
    private boolean witnessIsMissingVariables() {
        HashSet<String> missingWitnesses = getVariables();
        missingWitnesses.removeAll(witnessMapping.getMap().keySet());
        return !missingWitnesses.isEmpty();
    }

    public GeneralizedSchnorrPublicParameter getPp() {
        return pp;
    }

    @Override
    public SpecialHonestVerifierSimulator getSimulator() {
        return new GeneralizedSchnorrSimulator(this);
    }

    @Override
    public void setProblems(Problem[] problems) {
        super.setProblems(problems);
        this.isFulfilled = null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        GeneralizedSchnorrProtocol that = (GeneralizedSchnorrProtocol) o;
        return Objects.equals(pp, that.pp);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(super.hashCode(), pp);
        return result;
    }

    public static GeneralizedSchnorrResponse recreateResponse(Representation repr, Zp zp) {
        return new GeneralizedSchnorrResponse(repr.obj().get("variableName").str().get(),
                zp.getElement(repr.obj().get("value")));
    }
}
