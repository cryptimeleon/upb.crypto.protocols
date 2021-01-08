package de.upb.crypto.clarc.protocols.arguments.schnorr2;

import de.upb.crypto.clarc.protocols.SecretInput;
import de.upb.crypto.clarc.protocols.arguments.sigma.*;
import de.upb.crypto.math.expressions.Substitution;
import de.upb.crypto.math.expressions.bool.GroupEqualityExpr;
import de.upb.crypto.math.expressions.exponent.BasicNamedExponentVariableExpr;
import de.upb.crypto.math.expressions.group.GroupElementExpression;
import de.upb.crypto.math.expressions.group.GroupOpExpr;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.interfaces.structures.RingElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zn;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class DlogRepresentationFragment implements SchnorrFragment {
    private GroupElementExpression homomorphicPart;
    private final HashMap<String, SchnorrZnVariable> witnessVars = new HashMap<>();
    private GroupElement target;
    private Zn zn;

    /**
     * Instantiates this fragment to prove knowledge a witness (consisting of values for all BasicNamedExponentVariableExpr in homomorphicPart) such that
     * homomorphicPart(witness) = target;
     *
     * @param homomorphicPart an expression which is linear in its variables. If it contains BasicNamedExponentVariableExpr, those are interpreted as witnesses.
     * @param target the desired (public) image of homomorphicPart.
     */
    public DlogRepresentationFragment(GroupElementExpression homomorphicPart, GroupElement target) {
        init(homomorphicPart, target);
    }

    /**
     * Instantiates this fragment to prove knowledge a witness (consisting of all variables in the given equation) such that
     * the equation is fulfilled.
     *
     * @throws IllegalArgumentException if equation is not supported (i.e. framework is unable to write it as linear(witnesses) = constant)
     */
    public DlogRepresentationFragment(GroupEqualityExpr equation) throws IllegalArgumentException {
        GroupOpExpr linearized = equation.getLhs().op(equation.getRhs().inv()).linearize();
        init(linearized.getRhs(), linearized.getLhs().inv().evaluate());
    }

    private void init(GroupElementExpression homomorphicPart, GroupElement target) {
        this.zn = target.getStructure().getZn();
        this.homomorphicPart = homomorphicPart.substitute(
                variable -> variable instanceof BasicNamedExponentVariableExpr
                        ? witnessVars.computeIfAbsent(((BasicNamedExponentVariableExpr) variable).getName(), name -> new SchnorrZnVariable(name, zn))
                        : null
        );
        this.target = target;
    }

    @Override
    public SchnorrVariableList generateAnnouncementSecret(SecretInput secretInput) {
        //For each witness variable, choose a random assignment
        return chooseRandomWitnessValues();
    }

    @Override
    public Announcement generateAnnouncement(Function<SchnorrVariable, SchnorrVariableValue> outerRandom, SecretInput secretInput, AnnouncementSecret announcementSecret) {
        //Evaluate homomorphicPart with respect random variable assignements from the AnnouncementSecret and the random assignments coming from the outside.
        return new DlogRepresentationAnnouncement(
                evaluateHomomorphicPart((SchnorrVariableList) announcementSecret, outerRandom)
        );
    }

    @Override
    public Response generateResponse(SecretInput secretInput, AnnouncementSecret announcementSecret, Challenge challenge) {
        DlogRepresentationWitness witness = (DlogRepresentationWitness) secretInput;
        BigInteger challengeInt = ((SchnorrChallenge) challenge).getChallenge();

        //challenge * witness + random announcement value
        return new SchnorrVariableList(
                this.witnessVars.keySet().stream()
                        .sorted()
                        .map(name ->
                                new SchnorrZnVariableValue(
                                zn.valueOf(witness.get(name))
                                        .mul(challengeInt)
                                        .add(((SchnorrZnVariableValue) ((SchnorrVariableList) announcementSecret).getValue(witnessVars.get(name))).getValue())
                                , witnessVars.get(name))
                        )
                        .collect(Collectors.toList())
        );
    }

    @Override
    public boolean checkTranscript(Announcement announcement, Challenge challenge, Response response, Function<SchnorrVariable, SchnorrVariableValue> outerResponse) {
        //Check homomorphicPart(response) = announcement + c * target (additive group notation)
        GroupElement evaluatedResponse = evaluateHomomorphicPart((SchnorrVariableList) response, outerResponse);

        return evaluatedResponse.equals(((DlogRepresentationAnnouncement) announcement).announcement.op(target.pow(((SchnorrChallenge) challenge).getChallenge())));
    }

    @Override
    public SigmaProtocolTranscript generateSimulatedTranscript(Challenge challenge, Function<SchnorrVariable, SchnorrVariableValue> outerRandomResponse) {
        //Choose random response, set announcement such that transcript is accepting
        SchnorrVariableList response = chooseRandomWitnessValues();

        GroupElement announcement = evaluateHomomorphicPart(response, outerRandomResponse).op(target.pow(((SchnorrChallenge) challenge).getChallenge()).inv());

        return new SigmaProtocolTranscript(new DlogRepresentationAnnouncement(announcement), challenge, response);
    }

    @Override
    public Announcement recreateAnnouncement(Representation repr) {
        return new DlogRepresentationAnnouncement(target.getStructure().getElement(repr));
    }

    @Override
    public Response recreateResponse(Announcement announcement, Representation repr) {
        return new SchnorrVariableList(witnessVars.entrySet().stream().sorted(Map.Entry.comparingByKey()).map(Map.Entry::getValue).collect(Collectors.toList()), repr);
    }

    public static final class DlogRepresentationAnnouncement implements Announcement {
        public final GroupElement announcement;

        public DlogRepresentationAnnouncement(GroupElement announcement) {
            this.announcement = announcement;
        }

        @Override
        public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
            accumulator.append(announcement);
            return accumulator;
        }

        @Override
        public Representation getRepresentation() {
            return announcement.getRepresentation();
        }
    }

    public static final class DlogRepresentationWitness implements SecretInput {
        public final HashMap<String, BigInteger> values = new HashMap<>();

        /*public DlogRepresentationWitness(Map<String, BigInteger> witness) {
            values.putAll(witness);
        }*/

        public DlogRepresentationWitness(Map<String, ? extends RingElement> witness) {
            witness.forEach((k, v) -> values.put(k, v.asInteger()));
        }

        public BigInteger get(String name) {
            return values.get(name);
        }
    }

    private GroupElement evaluateHomomorphicPart(SchnorrVariableList innerVariableValues, Function<SchnorrVariable, SchnorrVariableValue> outerVariableValues) {
        return homomorphicPart.evaluate(
                Substitution.joinAndIgnoreNullpointers(
                        variableInHomomorphicPart -> innerVariableValues.getValue((SchnorrVariable) variableInHomomorphicPart).asExpression(),
                        variableInHomomorphicPart -> outerVariableValues.apply((SchnorrVariable) variableInHomomorphicPart).asExpression()
                )
        );
    }

    private SchnorrVariableList chooseRandomWitnessValues() {
        return new SchnorrVariableList(
                witnessVars.values().stream().map(SchnorrZnVariable::generateRandomValue).collect(Collectors.toList())
        );
    }
}
