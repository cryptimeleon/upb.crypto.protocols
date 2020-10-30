package de.upb.crypto.clarc.protocols.schnorr;

import de.upb.crypto.clarc.protocols.CommonInput;
import de.upb.crypto.clarc.protocols.SecretInput;
import de.upb.crypto.clarc.protocols.arguments.sigma.*;
import de.upb.crypto.clarc.protocols.schnorr.stmts.api.SchnorrStatement;
import de.upb.crypto.clarc.protocols.schnorr.stmts.api.SchnorrVariable;
import de.upb.crypto.clarc.protocols.schnorr.stmts.api.SchnorrVariableValue;
import de.upb.crypto.math.expressions.bool.BoolEmptyExpr;
import de.upb.crypto.math.expressions.bool.BooleanExpression;
import de.upb.crypto.math.random.interfaces.RandomGeneratorSupplier;
import de.upb.crypto.math.serialization.Representation;

import java.math.BigInteger;
import java.util.*;

public class SchnorrProtocol implements SigmaProtocol {
    protected List<SchnorrStatement> statements;

    public SchnorrProtocol(SchnorrStatement... statements) {
        this.statements = new ArrayList<>();
        this.statements.addAll(Arrays.asList(statements));
    }

    @Override
    public SchnorrAnnouncementSecret generateAnnouncementSecret(CommonInput commonInput, SecretInput secretInput) {
        //Ask for announcement secret of statements
        HashMap<String, AnnouncementSecret> statementSecrets = new HashMap<>();
        HashMap<String, Announcement> statementInternalAnnouncements = new HashMap<>();
        for (SchnorrStatement stmt : statements) {
            AnnouncementSecret secret = stmt.generateInternalAnnouncementSecret((SchnorrInput) commonInput, (SchnorrInput) secretInput);
            Announcement internalAnnouncement = stmt.generateInternalAnnouncement((SchnorrInput) commonInput, (SchnorrInput) secretInput, secret);
            statementSecrets.put(stmt.getName(), secret);
            statementInternalAnnouncements.put(stmt.getName(), internalAnnouncement);
        }

        //Choose a random preimage
        Set<SchnorrVariable> variables = getEffectivePreimageSpace(commonInput);
        HashMap<SchnorrVariable, SchnorrVariableValue> randomVariableValues = new HashMap<>();
        for (SchnorrVariable var : variables)
            randomVariableValues.put(var, var.getRandomValue());
        SchnorrPreimage randomPreimage = new SchnorrPreimage(randomVariableValues);

        return new SchnorrAnnouncementSecret(randomPreimage, statementSecrets, statementInternalAnnouncements);
    }

    @Override
    public SchnorrAnnouncement generateAnnouncement(CommonInput commonInput, SecretInput secretInput, AnnouncementSecret announcementSecret) {
        Map<String, Announcement> internalAnnouncements = ((SchnorrAnnouncementSecret) announcementSecret).getInternalAnnouncements();

        //Compute the random images
        HashMap<String, SchnorrImage> randomImages = new HashMap<>();
        for (SchnorrStatement stmt : statements)
            randomImages.put(stmt.getName(), stmt.evaluateHomomorphism((SchnorrInput) commonInput, internalAnnouncements.get(stmt.getName()), ((SchnorrAnnouncementSecret) announcementSecret).getRandomPreimage()));

        return new SchnorrAnnouncement(internalAnnouncements, randomImages);
    }

    @Override
    public SchnorrChallenge generateChallenge(CommonInput commonInput) {
        BigInteger challengeSpaceSize = statements.stream()
                .map(stmt -> stmt.getChallengeSpaceSize((SchnorrInput) commonInput))
                .min(BigInteger::compareTo)
                .orElseThrow(IllegalArgumentException::new);
        return new SchnorrChallenge(RandomGeneratorSupplier.getRnd().getRandomElement(challengeSpaceSize));
    }

    @Override
    public Response generateResponse(CommonInput commonInput, SecretInput secretInput, Announcement announcement, AnnouncementSecret announcementSecret, Challenge challenge) {
        HashMap<SchnorrVariable, SchnorrVariableValue> response = new HashMap<>();

        //Repsonse: for each variable, it's witness * challenge + randomPreimageFromAnnouncementSecret
        for (SchnorrVariable variable : getEffectivePreimageSpace(commonInput)) {
            SchnorrVariableValue witness;
            if (variable.isInternalVariable()) {
                SchnorrStatement statement = variable.getStatement();
                Announcement internalAnnouncement = ((SchnorrAnnouncement) announcement).getInternalAnnouncement(statement.getName());
                AnnouncementSecret internalAnnouncementSecret = ((SchnorrAnnouncementSecret) announcementSecret).getStatementAnnouncementSecret(statement.getName());
                witness = variable.getStatement().getInternalWitnessValue((SchnorrInput) commonInput, (SchnorrInput) secretInput, internalAnnouncement, internalAnnouncementSecret, variable);
            } else
                witness = variable.instantiateFromInput((SchnorrInput) secretInput);
            SchnorrVariableValue blindedWitness = witness.evalLinear(((SchnorrChallenge) challenge).getChallenge(), ((SchnorrAnnouncementSecret) announcementSecret).getRandomPreimage().getValue(variable));
            response.put(variable, blindedWitness);
        }

        return new SchnorrPreimage(response);
    }

    @Override
    public BooleanExpression getTranscriptCheckExpression(CommonInput commonInput, Announcement announcement, Challenge challenge, Response response) {
        BooleanExpression expr = new BoolEmptyExpr();
        for (SchnorrStatement stmt : statements) {
            Announcement internalAnnouncement = ((SchnorrAnnouncement) announcement).getInternalAnnouncement(stmt.getName());
            SchnorrImage randomImageFromAnnouncement = ((SchnorrAnnouncement) announcement).getRandomImage(stmt.getName());
            expr = expr.and( //(TargetImage ^ challenge) * randomImageFromAnnouncement = hom(response)
                    stmt.getHomomorphismTarget((SchnorrInput) commonInput, internalAnnouncement)
                            .pow(((SchnorrChallenge) challenge).getChallenge())
                            .op(randomImageFromAnnouncement)
                    .isEqualTo(stmt.evaluateHomomorphism((SchnorrInput) commonInput, internalAnnouncement, ((SchnorrPreimage) response)))
            );
        }

        return expr;
    }

    public SchnorrImage applyHomomorphismOnWitness(CommonInput commonInput, SecretInput secretInput, Announcement announcement, AnnouncementSecret announcementSecret, SchnorrStatement stmt) {
        SchnorrPreimage preimage = getEffectiveWitness(commonInput, secretInput, announcement, announcementSecret);
        return stmt.evaluateHomomorphism((SchnorrInput) commonInput, ((SchnorrAnnouncement) announcement).getInternalAnnouncement(stmt.getName()), preimage);
    }

    public SchnorrPreimage getEffectiveWitness(CommonInput commonInput, SecretInput secretInput, Announcement announcement, AnnouncementSecret announcementSecret) {
        HashMap<SchnorrVariable, SchnorrVariableValue> values = new HashMap<>();
        for (SchnorrVariable variable : getEffectivePreimageSpace(commonInput)) {
            SchnorrVariableValue witness;
            if (variable.isInternalVariable()) {
                SchnorrStatement statement = variable.getStatement();
                Announcement internalAnnouncement = ((SchnorrAnnouncement) announcement).getInternalAnnouncement(statement.getName());
                AnnouncementSecret internalAnnouncementSecret = ((SchnorrAnnouncementSecret) announcementSecret).getStatementAnnouncementSecret(statement.getName());
                witness = variable.getStatement().getInternalWitnessValue((SchnorrInput) commonInput, (SchnorrInput) secretInput, internalAnnouncement, internalAnnouncementSecret, variable);
            } else
                witness = variable.instantiateFromInput((SchnorrInput) secretInput);
            values.put(variable, witness);
        }
        return new SchnorrPreimage(values);
    }

    @Override
    public SpecialHonestVerifierZkSimulator getSimulator() {
        return new SchnorrSimulator(this);
    }

    @Override
    public Announcement recreateAnnouncement(Representation repr, CommonInput commonInput) {
        HashMap<String, Announcement> internalAnnouncements = new HashMap<>();
        HashMap<String, SchnorrImage> randomImages = new HashMap<>();
        for (SchnorrStatement stmt : statements) {
            internalAnnouncements.put(stmt.getName(), stmt.recreateInternalAnnouncement((SchnorrInput) commonInput, repr.obj().get("announcements").obj().get(stmt.getName())));
            randomImages.put(stmt.getName(), stmt.recreateImage((SchnorrInput) commonInput, repr.obj().get("images").obj().get(stmt.getName())));
        }

        return new SchnorrAnnouncement(internalAnnouncements, randomImages);
    }

    @Override
    public SchnorrChallenge recreateChallenge(Representation repr, CommonInput commonInput) {
        return new SchnorrChallenge(repr);
    }

    @Override
    public SchnorrPreimage recreateResponse(Representation repr, CommonInput commonInput) {
        return recreateSchnorrPreimage(repr, commonInput);
    }

    public SchnorrPreimage recreateSchnorrPreimage(Representation repr, CommonInput commonInput) {
        HashMap<SchnorrVariable, SchnorrVariableValue> result = new HashMap<>();
        for (SchnorrVariable var : getEffectivePreimageSpace(commonInput)) {
            String scope = var.getScopeString();
            SchnorrVariableValue val = var.recreateValue(repr.obj().get(scope).obj().get(var.getName()));
            result.put(var, val);
        }

        return new SchnorrPreimage(result);
    }

    protected Set<SchnorrVariable> getEffectivePreimageSpace(CommonInput commonInput) {
        Set<SchnorrVariable> variables = new HashSet<>();
        for (SchnorrStatement stmt : statements) {
            variables.addAll(stmt.getWitnesses((SchnorrInput) commonInput));
        }

        return variables;
    }
}
