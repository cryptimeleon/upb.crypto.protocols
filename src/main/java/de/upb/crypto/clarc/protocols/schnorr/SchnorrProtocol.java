package de.upb.crypto.clarc.protocols.schnorr;

import de.upb.crypto.clarc.protocols.CommonInput;
import de.upb.crypto.clarc.protocols.SecretInput;
import de.upb.crypto.clarc.protocols.arguments.sigma.*;
import de.upb.crypto.math.expressions.Expression;
import de.upb.crypto.math.expressions.bool.*;
import de.upb.crypto.math.expressions.exponent.ExponentConstantExpr;
import de.upb.crypto.math.expressions.group.GroupElementExpression;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.random.interfaces.RandomGeneratorSupplier;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zn;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SchnorrProtocol implements SigmaProtocol { //TODO handle precomputation (either make user do it, offer it here, or enforce it always)
    /**
     * Schnorr proves knowledge of x s.t. Ψ(x) = y for a public y.
     * The homomorphicPart is x (as an expression that we interpret as a homomorphism through expr.evaluate(substitutionMap))
     */
    protected List<GroupElementExpression> homomorphicPart;

    /**
     * Schnorr proves knowledge of x s.t. Ψ(x) = y for a public y.
     * The constantPart is y.
     */
    protected List<GroupElementExpression> constantPart;

    /**
     * Instantiates this class with the given statements.
     * <p>
     * Variables within the statement(s) can later be substituted by common input, and additional statements can be added.
     * In the most extreme case, you can pass an empty list here and push all desired the statements into CommonInput.
     * Generally, it's advantageous to put as many statements as possible already into the constructor and do few substitutions through CommonInput,
     * as precomputations can be more effective this way.
     * If you do not want to run precomputations for this protocol, you should pass an empty list of statements here.
     *
     * After substitution applied by CommonInput, the expressions must be of the form A = B, where A is a GroupElementExpression
     * that is homomorphic w.r.t. the remaining variables (i.e. A.substitute(x).op(A.substitute(y)) evaluates to the same as A.substitute(x.add(y))),
     * and B is effectively a constant (!B.containsVariables())
     */
    public SchnorrProtocol(Iterable<GroupEqualityExpr> statements) {
        this.homomorphicPart = new ArrayList<>();
        this.constantPart = new ArrayList<>();
        for (GroupEqualityExpr expr : statements) {
            homomorphicPart.add(expr.getLhs());
            constantPart.add(expr.getRhs());
        }
    }

    /**
     * Instantiates the protocol for expressions of the form "X_0 = X_1 AND X_2 = X_3 AND ..."
     */
    public SchnorrProtocol(BooleanExpression statement) {
        this.homomorphicPart = new ArrayList<>();
        this.constantPart = new ArrayList<>();
        statement.treeWalk(node -> {
            if (node instanceof BooleanExpression &&
                    !(node instanceof BoolAndExpr || node instanceof GroupEqualityExpr || node instanceof ExponentEqualityExpr))
                throw new IllegalArgumentException("Expression must only consist of AND expresisons and equalities between group elements or exponents");

            if (node instanceof GroupEqualityExpr) {
                this.homomorphicPart.add(((GroupEqualityExpr) node).getLhs());
                this.constantPart.add(((GroupEqualityExpr) node).getRhs());
            }
        });
    }

    protected List<GroupElementExpression> getEffectiveHomomorphicPart(SchnorrCommonInput commonInput) {
        ArrayList<GroupElementExpression> effective = new ArrayList<>();

        //Add substituted homomorphic part object var
        Map<String, Expression> substitutionMap = commonInput.getSubstitutionMap();
        if (!substitutionMap.isEmpty())
            for (GroupElementExpression expr : homomorphicPart)
                effective.add(expr.substitute(substitutionMap::get));

        //Add additional homomorphic parts
        effective.addAll(commonInput.getAdditionalHomomorphicPart());

        return effective;
    }

    protected List<GroupElementExpression> getEffectiveConstantPart(SchnorrCommonInput commonInput) {
        ArrayList<GroupElementExpression> effective = new ArrayList<>();

        //Add substituted constant part object var
        Map<String, Expression> substitutionMap = commonInput.getSubstitutionMap();
        if (!substitutionMap.isEmpty())
            for (GroupElementExpression expr : constantPart)
                effective.add(expr.substitute(substitutionMap::get));

        //Add additional constant parts
        effective.addAll(commonInput.getAdditionalConstantPart());

        return effective;
    }

    /**
     * Returns a map that maps each (exponent) variable name in the homomorphic part to the group size it belongs to.
     */
    protected HashMap<String, Zn> getZgroupSizes(List<GroupElementExpression> effectiveHomomorphicPart) {
        HashMap<String, Zn> result = new HashMap<>();
        for (int i=0;i<effectiveHomomorphicPart.size();i++) {
            for (String variable : effectiveHomomorphicPart.get(i).getVariables()) {
                Zn current = result.get(variable);
                if (current == null)
                    result.put(variable, effectiveHomomorphicPart.get(i).getGroup().getZn());
                else if (!current.equals(effectiveHomomorphicPart.get(i).getGroup().getZn()))
                    throw new IllegalArgumentException("Exponent "+variable+" used for two different group sizes");
            }
        }
        return result;
    }

    @Override
    public AnnouncementSecret generateAnnouncementSecret(CommonInput commonInput, SecretInput secretInput) {
        return generateAnnouncementSecret(getEffectiveHomomorphicPart((SchnorrCommonInput) commonInput));
    }

    protected AnnouncementSecret generateAnnouncementSecret(List<GroupElementExpression> effectiveHomomorphicPart) {
        HashMap<String, BigInteger> result = new HashMap<>();

        for (Map.Entry<String, Zn> entry : getZgroupSizes(effectiveHomomorphicPart).entrySet())
            result.put(entry.getKey(), entry.getValue().getUniformlyRandomElement().getInteger());

        return new SchnorrVariableInstantiation(result);
    }

    @Override
    public SchnorrAnnouncement generateAnnouncement(CommonInput commonInput, SecretInput secretInput, AnnouncementSecret announcementSecret) {
        return generateAnnouncement(getEffectiveHomomorphicPart((SchnorrCommonInput) commonInput), (SchnorrVariableInstantiation) announcementSecret);
    }

    protected SchnorrAnnouncement generateAnnouncement(List<GroupElementExpression> effectiveHomomorphicPart, SchnorrVariableInstantiation announcementSecret) {
        ArrayList<GroupElement> result = new ArrayList<>();

        for (int i=0;i<effectiveHomomorphicPart.size();i++) {
            result.add(effectiveHomomorphicPart.get(i).evaluate(name -> {
                BigInteger elem = announcementSecret.getValue(name);
                return elem == null ? null : new ExponentConstantExpr(elem);
            }));
        }

        return new SchnorrAnnouncement(result);
    }

    @Override
    public SchnorrChallenge generateChallenge(CommonInput commonInput) {
        return generateChallenge(getEffectiveConstantPart((SchnorrCommonInput) commonInput));
    }

    protected SchnorrChallenge generateChallenge(List<GroupElementExpression> effectiveConstantPart) {
        BigInteger minSize = effectiveConstantPart.get(0).getGroup().size();
        for (int i=1;i<effectiveConstantPart.size();i++)
            minSize = minSize.min(effectiveConstantPart.get(i).getGroup().size());

        //Choose challenge from Z_minSize
        return new SchnorrChallenge(RandomGeneratorSupplier.getRnd().getRandomElement(minSize));
    }

    @Override
    public SchnorrVariableInstantiation generateResponse(CommonInput commonInput, SecretInput secretInput, Announcement announcement, AnnouncementSecret announcementSecret, Challenge challenge) {
        return generateResponse(getEffectiveHomomorphicPart((SchnorrCommonInput) commonInput),
                (SchnorrVariableInstantiation) secretInput,
                (SchnorrVariableInstantiation) announcementSecret,
                (SchnorrChallenge) challenge);
    }

    protected SchnorrVariableInstantiation generateResponse(List<GroupElementExpression> effectiveHomomorphicPart, SchnorrVariableInstantiation secretInput, SchnorrVariableInstantiation announcementSecret, SchnorrChallenge challenge) {
        HashMap<String, BigInteger> response = new HashMap<>();
        HashMap<String, Zn> groupSizes = getZgroupSizes(effectiveHomomorphicPart);
        for (String variable : groupSizes.keySet()) {
            response.put(variable, secretInput.getValue(variable)
                    .multiply(challenge.getChallenge())
                    .add(announcementSecret.getValue(variable))
                    .mod(groupSizes.get(variable).size()));
        }

        return new SchnorrVariableInstantiation(response);
    }

    @Override
    public boolean checkTranscript(CommonInput commonInput, Announcement announcement, Challenge challenge, Response response) {
        return getTranscriptCheckExpression(commonInput, announcement, challenge, response).evaluate();
    }

    @Override
    public BooleanExpression getTranscriptCheckExpression(CommonInput commonInput, Announcement announcement, Challenge challenge, Response response) {
        return getTranscriptCheckExpression(getEffectiveHomomorphicPart((SchnorrCommonInput) commonInput),
                getEffectiveConstantPart((SchnorrCommonInput) commonInput),
                (SchnorrAnnouncement) announcement,
                (SchnorrChallenge) challenge,
                (SchnorrVariableInstantiation) response);
    }

    protected BooleanExpression getTranscriptCheckExpression(List<GroupElementExpression> effectiveHomomorphicPart, List<GroupElementExpression> effectiveConstantPart, SchnorrAnnouncement announcement, SchnorrChallenge challenge, SchnorrVariableInstantiation response) {
        BooleanExpression result = new BoolEmptyExpr();
        for (int i=0;i<effectiveHomomorphicPart.size();i++)
            result = result.and(new GroupEqualityExpr(
                    effectiveHomomorphicPart.get(i).substitute(name -> new ExponentConstantExpr(response.getValue(name))),
                    effectiveConstantPart.get(i).pow(challenge.getChallenge()).op(announcement.announcements.get(i))));

        return result;
    }

    @Override
    public SpecialHonestVerifierZkSimulator getSimulator() {
        return new SchnorrSimulator(this);
    }

    @Override
    public Announcement recreateAnnouncement(Representation repr) {
        ArrayList<GroupElement> elems = new ArrayList<>();
        for (int i=0;i<constantPart.size();i++)
            elems.add(constantPart.get(i).getGroup().getElement(repr.list().get(i)));

        return new SchnorrAnnouncement(elems);
    }

    @Override
    public Challenge recreateChallenge(Representation repr) {
        return new SchnorrChallenge(repr);
    }

    @Override
    public Response recreateResponse(Representation repr) {
        return new SchnorrVariableInstantiation(repr);
    }
}
