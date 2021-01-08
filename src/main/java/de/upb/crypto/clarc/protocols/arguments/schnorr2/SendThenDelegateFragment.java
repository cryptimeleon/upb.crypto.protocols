package de.upb.crypto.clarc.protocols.arguments.schnorr2;

import de.upb.crypto.clarc.protocols.SecretInput;
import de.upb.crypto.clarc.protocols.arguments.sigma.*;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrChallenge;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.interfaces.structures.Element;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.interfaces.structures.Structure;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zn;

import java.math.BigInteger;
import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;

public abstract class SendThenDelegateFragment implements SchnorrFragment {
    protected abstract SendFirstSecret provideSendFirstSecret(SecretInput secretInput);
    protected abstract SendFirstValue provideSendFirstValue(SecretInput secretInput, SendFirstSecret sendFirstSecret);
    protected abstract SendFirstValue recreateSendFirstValue(Representation repr);
    protected abstract SendFirstValue simulateSendFirstValue();

    protected abstract SubprotocolSpec provideSubprotocolSpec(SendFirstValue sendFirstValue);
    protected abstract SubprotocolSpecSecrets provideSubprotocolSpecSecrets(SubprotocolSpec spec, SecretInput secretInput, SendFirstSecret sendFirstSecret);

    protected abstract boolean provideAdditionalCheck(SendFirstValue sendFirstValue);

    @Override
    public AnnouncementSecret generateAnnouncementSecret(SecretInput secretInput) {
        //Ask implementing class for secrets
        SendFirstSecret sendFirstSecret = provideSendFirstSecret(secretInput);
        SendFirstValue sendFirstValue = provideSendFirstValue(secretInput, sendFirstSecret);
        SubprotocolSpec subprotocolSpec = provideSubprotocolSpec(sendFirstValue);
        SubprotocolSpecSecrets subprotocolSpecSecrets = provideSubprotocolSpecSecrets(subprotocolSpec, secretInput, sendFirstSecret);

        //Generate announcement secrets
        HashMap<String, AnnouncementSecret> subprotocolAnnouncementSecrets = new HashMap<>();
        subprotocolSpec.mapSubprotocols((name, subprotocol) -> subprotocol.generateAnnouncementSecret(subprotocolSpecSecrets.getSecretInput(name)));

        //Generate random assignment of knowledge variables
        HashMap<SchnorrVariable, SchnorrVariableValue> randomVariableValues = new HashMap<>();
        subprotocolSpec.forEachVariable((name, variable) -> randomVariableValues.put(variable, variable.generateRandomValue()));

        return new SendThenDelegateAnnouncementSecret(randomVariableValues, sendFirstSecret, sendFirstValue, subprotocolSpec, subprotocolSpecSecrets, subprotocolAnnouncementSecrets);
    }

    @Override
    public Announcement generateAnnouncement(Function<SchnorrVariable, SchnorrVariableValue> outerRandom, SecretInput secretInput, AnnouncementSecret announcementSecret) {
        SendThenDelegateAnnouncementSecret announcementSecret1 = (SendThenDelegateAnnouncementSecret) announcementSecret;

        Map<String, Announcement> subprotocolAnnouncements = announcementSecret1.subprotocolSpec.mapSubprotocols(
                (name, fragment) -> fragment.generateAnnouncement(
                        schnorrVar -> announcementSecret1.randomVariableValues.containsKey(schnorrVar) ? announcementSecret1.randomVariableValues.get(schnorrVar): outerRandom.apply(schnorrVar),
                        announcementSecret1.subprotocolSpecSecrets.getSecretInput(name),
                        announcementSecret1.subprotocolAnnouncementSecret.get(name)
                )
        );

        return new SendThenDelegateAnnouncement(subprotocolAnnouncements, announcementSecret1.sendFirstValue);
    }

    @Override
    public Response generateResponse(SecretInput secretInput, AnnouncementSecret announcementSecret, Challenge challenge) {
        SendThenDelegateAnnouncementSecret announcementSecret1 = (SendThenDelegateAnnouncementSecret) announcementSecret;

        //Subprotocol responses
        Map<String, Response> subprotocolResponses = announcementSecret1.subprotocolSpec.mapSubprotocols((subprotocolName, subprotocol) -> subprotocol.generateResponse(
                announcementSecret1.subprotocolSpecSecrets.getSecretInput(subprotocolName),
                announcementSecret1.subprotocolAnnouncementSecret.get(subprotocolName),
                challenge
        ));

        //challenge * witness + announcement for knowledge variables
        SchnorrVariableList knowledgeVarResponse = new SchnorrVariableList(
                announcementSecret1.subprotocolSpecSecrets.mapWitnessesInOrder((name, witnessValue) ->
                        witnessValue.evalLinear(((SchnorrChallenge) challenge).getChallenge(), announcementSecret1.randomVariableValues.get(name))
                )
        );

        return new SendThenDelegateResponse(subprotocolResponses, knowledgeVarResponse);
    }

    @Override
    public boolean checkTranscript(Announcement announcement, Challenge challenge, Response response, Function<SchnorrVariable, SchnorrVariableValue> outerResponse) {
        SendFirstValue sendFirstValue = ((SendThenDelegateAnnouncement) announcement).sendFirstValue;
        SubprotocolSpec subprotocolSpec = provideSubprotocolSpec(sendFirstValue);

        //Check that subprotocol accept
        try {
            subprotocolSpec.forEachProtocol((name, subprotocol) -> {
                if (!subprotocol.checkTranscript(
                            ((SendThenDelegateAnnouncement) announcement).subprotocolAnnouncements.get(name),
                            challenge,
                            ((SendThenDelegateResponse) response).subprotocolResponses.get(name),
                            schnorrVar -> {
                                if (subprotocolSpec.containsVariable(schnorrVar)) //one of our variables
                                    return ((SendThenDelegateResponse) response).variableResponses.getValue(schnorrVar);
                                return outerResponse.apply(schnorrVar); //an outside variable
                            }
                        )
                ) {
                    throw new RuntimeException("Subprotocol " + name + " does not accept its subtranscript");
                }
            });
        } catch (RuntimeException e) {
            System.err.println(e.getMessage());
            return false;
        }

        return provideAdditionalCheck(sendFirstValue);
    }

    @Override
    public SigmaProtocolTranscript generateSimulatedTranscript(Challenge challenge, Function<SchnorrVariable, SchnorrVariableValue> outerRandomResponse) {
        SendFirstValue sendFirstValue = simulateSendFirstValue();
        SubprotocolSpec subprotocolSpec = provideSubprotocolSpec(sendFirstValue);

        //Simulate our own knowledge variables by choosing a random response for them
        SchnorrVariableList randomResponses = new SchnorrVariableList(subprotocolSpec.mapVariables((name, variable) -> variable.generateRandomValue()));

        //Ask subprotocols to simulate their transcripts
        Map<String, SigmaProtocolTranscript> subprotocolTranscripts = subprotocolSpec.mapSubprotocols((name, fragment) -> fragment.generateSimulatedTranscript(challenge, schnorrVar -> {
            if (subprotocolSpec.containsVariable(schnorrVar)) //one of our variables
                return randomResponses.getValue(schnorrVar);
            return outerRandomResponse.apply(schnorrVar); //an outside variable
        }));

        //That's it. Collect what we have.
        HashMap<String, Announcement> subprotocolAnnouncements = new HashMap<>();
        HashMap<String, Response> subprotocolResponses = new HashMap<>();
        subprotocolTranscripts.forEach((name, transcript) -> {
            subprotocolAnnouncements.put(name, transcript.getAnnouncement());
            subprotocolResponses.put(name, transcript.getResponse());
        });

        return new SigmaProtocolTranscript(
                new SendThenDelegateAnnouncement(subprotocolAnnouncements, sendFirstValue),
                challenge,
                new SendThenDelegateResponse(subprotocolResponses, randomResponses)
        );
    }

    @Override
    public Announcement recreateAnnouncement(Representation repr) {
        SendFirstValue sendFirstValue = recreateSendFirstValue(repr.list().get(0));
        SubprotocolSpec subprotocolSpec = provideSubprotocolSpec(sendFirstValue);
        HashMap<String, Announcement> subprotocolAnnouncements = new HashMap<>();
        List<Map.Entry<String, SchnorrFragment>> subprotocolList = subprotocolSpec.getOrderedListOfSubprotocolsAndNames();

        for (int i=0;i<subprotocolList.size();i++)
            subprotocolAnnouncements.put(subprotocolList.get(i).getKey(), subprotocolList.get(i).getValue().recreateAnnouncement(repr.list().get(i+1)));

        return new SendThenDelegateAnnouncement(subprotocolAnnouncements, sendFirstValue);
    }

    @Override
    public Response recreateResponse(Announcement announcement, Representation repr) {
        SendFirstValue sendFirstValue = ((SendThenDelegateAnnouncement) announcement).sendFirstValue;
        SubprotocolSpec subprotocolSpec = provideSubprotocolSpec(sendFirstValue);

        SchnorrVariableList variableResponses = new SchnorrVariableList(subprotocolSpec.getOrderedListOfVariables(), repr.list().get(0));

        Map<String, Response> subprotocolResponses = new HashMap<>();

        List<Map.Entry<String, SchnorrFragment>> subprotocols = subprotocolSpec.getOrderedListOfSubprotocolsAndNames();
        for (int i=0;i<subprotocols.size();i++) {
            String name = subprotocols.get(i).getKey();
            SchnorrFragment subprotocol = subprotocols.get(i).getValue();
            subprotocolResponses.put(name, subprotocol.recreateResponse(((SendThenDelegateAnnouncement) announcement).subprotocolAnnouncements.get(name), repr.list().get(i+1)));
        }

        return new SendThenDelegateResponse(subprotocolResponses, variableResponses);
    }

    public interface SendFirstSecret {

    }

    public static class BasicSendFirstSecret implements SendFirstSecret {
        private final HashMap<String, GroupElement> groupElems = new HashMap<>();
        private final HashMap<String, Zn.ZnElement> znElems = new HashMap<>();
        private final HashMap<String, BigInteger> bigInts = new HashMap<>();
        private final HashMap<String, Object> objects = new HashMap<>();

        public BasicSendFirstSecret putGroupElement(String key, GroupElement groupElement) {
            groupElems.put(key, groupElement);
            return this;
        }

        public BasicSendFirstSecret putZnElement(String key, Zn.ZnElement znElement) {
            znElems.put(key, znElement);
            return this;
        }

        public BasicSendFirstSecret putInteger(String key, BigInteger integer) {
            bigInts.put(key, integer);
            return this;
        }

        public BasicSendFirstSecret putObject(String key, Object obj) {
            objects.put(key, obj);
            return this;
        }

        public GroupElement getGroupElem(String key) {
            return groupElems.get(key);
        }

        public Zn.ZnElement getZnElem(String key) {
            return znElems.get(key);
        }

        public BigInteger getInt(String key) {
            return bigInts.get(key);
        }

        public <T> T getObject(String key, Class<T> clazz) {
            return clazz.cast(objects.get(key));
        }
    }

    public interface SendFirstValue extends Representable, UniqueByteRepresentable {

    }

    public static class AlgebraicSendFirstValue implements SendFirstValue {
        @UniqueByteRepresented
        private final List<Element> elements = new ArrayList<>();

        public AlgebraicSendFirstValue(Element... values) {
            elements.addAll(Arrays.asList(values));
        }

        public AlgebraicSendFirstValue(Representation repr, Structure... structures) {
            for (int i=0;i<structures.length;i++)
                elements.add(structures[i].getElement(repr.list().get(i)));
        }

        public Element getElement(int i) {
            return elements.get(i);
        }

        public GroupElement getGroupElement(int i) {
            return (GroupElement) getElement(i);
        }

        public Zn.ZnElement getZnElement(int i) {
            return (Zn.ZnElement) getElement(i);
        }

        @Override
        public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
            AnnotatedUbrUtil.autoAccumulate(accumulator,this);
            return accumulator;
        }

        @Override
        public Representation getRepresentation() {
            ListRepresentation repr = new ListRepresentation();
            elements.forEach(elem -> repr.add(elem.getRepresentation()));
            return repr;
        }
    }

    public static class SendThenDelegateAnnouncementSecret implements AnnouncementSecret {
        final HashMap<SchnorrVariable, SchnorrVariableValue> randomVariableValues;
        final SendFirstSecret sendFirstSecret;
        final SendFirstValue sendFirstValue;

        final SubprotocolSpec subprotocolSpec;
        final SubprotocolSpecSecrets subprotocolSpecSecrets;
        final HashMap<String, AnnouncementSecret> subprotocolAnnouncementSecret;

        public SendThenDelegateAnnouncementSecret(HashMap<SchnorrVariable, SchnorrVariableValue> randomVariableValues, SendFirstSecret sendFirstSecret, SendFirstValue sendFirstValue, SubprotocolSpec subprotocolSpec, SubprotocolSpecSecrets subprotocolSpecSecrets, HashMap<String, AnnouncementSecret> subprotocolAnnouncementSecret) {
            this.randomVariableValues = randomVariableValues;
            this.sendFirstSecret = sendFirstSecret;
            this.sendFirstValue = sendFirstValue;
            this.subprotocolSpec = subprotocolSpec;
            this.subprotocolSpecSecrets = subprotocolSpecSecrets;
            this.subprotocolAnnouncementSecret = subprotocolAnnouncementSecret;
        }
    }

    public static class SendThenDelegateAnnouncement implements Announcement {
        @UniqueByteRepresented
        public final HashMap<String, Announcement> subprotocolAnnouncements = new HashMap<>();
        @UniqueByteRepresented
        public final SendFirstValue sendFirstValue;

        public SendThenDelegateAnnouncement(Map<String, ? extends Announcement> subprotocolAnnouncements, SendFirstValue sendFirstValue) {
            this.subprotocolAnnouncements.putAll(subprotocolAnnouncements);
            this.sendFirstValue = sendFirstValue;
        }

        @Override
        public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
            AnnotatedUbrUtil.autoAccumulate(accumulator,this);
            return accumulator;
        }

        @Override
        public Representation getRepresentation() {
            //Format: [sendFirstValue, subprotocol1Annoucement, subprotocol2Announcement, ...] - ordered lexicographically by name.
            ListRepresentation result = new ListRepresentation();
            result.add(sendFirstValue.getRepresentation());
            subprotocolAnnouncements.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .map(Map.Entry::getValue)
                    .map(Announcement::getRepresentation)
                    .forEachOrdered(result::add);

            return result;
        }
    }

    private static class SendThenDelegateResponse implements Response {
        @UniqueByteRepresented
        private Map<String, Response> subprotocolResponses;
        @UniqueByteRepresented
        private SchnorrVariableList variableResponses;

        public SendThenDelegateResponse(Map<String, Response> subprotocolResponses, SchnorrVariableList variableResponses) {
            this.subprotocolResponses = subprotocolResponses;
            this.variableResponses = variableResponses;
        }

        @Override
        public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
            return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
        }

        @Override
        public Representation getRepresentation() {
            //Format: [variableResponse, subprotocol1Response, subprotocol2Response, ...] //subprotocols ordered lexicographically by name

            ListRepresentation result = new ListRepresentation();
            result.add(variableResponses.getRepresentation());
            subprotocolResponses.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .map(Map.Entry::getValue)
                    .forEachOrdered(v -> result.add(v.getRepresentation()));

            return result;
        }
    }

    protected class SubprotocolSpec {
        private Map<String, SchnorrFragment> subprotocols;
        private Map<String, SchnorrVariable> variables;

        private SubprotocolSpec(Map<String, SchnorrFragment> subprotocols, Map<String, SchnorrVariable> variables) {
            this.subprotocols = subprotocols;
            this.variables = variables;
        }

        public <T> Map<String, T> mapSubprotocols(BiFunction<String, SchnorrFragment, T> mapper) {
            HashMap<String, T> result = new HashMap<>();
            subprotocols.forEach((name, subprotocol) -> result.put(name, mapper.apply(name, subprotocol)));
            return result;
        }

        public <T> List<T> mapVariables(BiFunction<String, SchnorrVariable, T> mapper) {
            ArrayList<T> result = new ArrayList<>();
            variables.forEach((name, variable) -> result.add(mapper.apply(name,variable)));
            return result;
        }

        public void forEachVariable(BiConsumer<String, SchnorrVariable> consumer) {
            variables.forEach(consumer);
        }

        public void forEachProtocol(BiConsumer<String, SchnorrFragment> consumer) {
            subprotocols.forEach(consumer);
        }

        public Collection<SchnorrFragment> getSubprotocols() {
            return subprotocols.values();
        }

        public void forEachVariableOrdered(BiConsumer<String, SchnorrVariable> consumer) {
            getOrderedListOfVariablesAndNames().forEach(e -> consumer.accept(e.getKey(), e.getValue()));
        }

        public void forEachProtocolOrdered(BiConsumer<String, SchnorrFragment> consumer) {
            getOrderedListOfSubprotocolsAndNames().forEach(e -> consumer.accept(e.getKey(), e.getValue()));
        }

        public List<Map.Entry<String, SchnorrFragment>> getOrderedListOfSubprotocolsAndNames() {
            return subprotocols.entrySet().stream().sorted(Map.Entry.comparingByKey()).collect(Collectors.toList());
        }

        public List<Map.Entry<String, SchnorrVariable>> getOrderedListOfVariablesAndNames() {
            return variables.entrySet().stream().sorted(Map.Entry.comparingByKey()).collect(Collectors.toList());
        }

        public List<SchnorrVariable> getOrderedListOfVariables() {
            return variables.entrySet().stream().sorted(Map.Entry.comparingByKey()).map(Map.Entry::getValue).collect(Collectors.toList());
        }

        public boolean containsSubprotocol(String subprotocolName) {
            return subprotocols.containsKey(subprotocolName);
        }

        public boolean containsVariable(String variableName) {
            return variables.containsKey(variableName);
        }

        public boolean containsVariable(SchnorrVariable variable) {
            return variables.get(variable.name) == variable;
        }
    }

    public class SubprotocolSpecBuilder {
        private HashMap<String, SchnorrFragment> subprotocols = new HashMap<>();
        private HashMap<String, SchnorrVariable> variables = new HashMap<>();
        private boolean isBuilt = false;

        public SubprotocolSpec build() {
            isBuilt = true;
            return new SubprotocolSpec(subprotocols, variables);
        }

        public SchnorrZnVariable addZnVariable(String name, Zn zn) {
            return addVariable(name, new SchnorrZnVariable(name, zn));
        }

        public SchnorrGroupElemVariable addGroupElemVariable(String name, Group group) {
            return addVariable(name, new SchnorrGroupElemVariable(name, group));
        }

        public void addSubprotocol(String name, SchnorrFragment fragment) {
            checkIsBuilt();
            if (subprotocols.containsKey(name))
                throw new IllegalArgumentException("Subprotocol with name "+name+" already exists.");
            subprotocols.put(name, fragment);
        }

        private <T extends SchnorrVariable> T addVariable(String name, T variable) {
            checkIsBuilt();
            if (variables.containsKey(name))
                throw new IllegalArgumentException("Variable with name "+name+" already exists.");

            variables.put(name, variable);
            return variable;
        }

        private void checkIsBuilt() {
            if (isBuilt)
                throw new IllegalStateException("Builder already finished.");
        }
    }

    public static class SubprotocolSpecSecrets {
        private final Map<String, SchnorrVariableValue> witnessesForVariables;
        private final Map<String, SecretInput> secretInputForSubprotocols;

        private SubprotocolSpecSecrets(Map<String, SchnorrVariableValue> witnessesForVariables, Map<String, SecretInput> secretInputForSubprotocols) {
            this.witnessesForVariables = witnessesForVariables;
            this.secretInputForSubprotocols = secretInputForSubprotocols;
        }

        SecretInput getSecretInput(String subprotocolName) {
            return secretInputForSubprotocols.get(subprotocolName);
        }

        public <T> List<T> mapWitnessesInOrder(BiFunction<String, SchnorrVariableValue, T> mapper) {
            ArrayList<T> result = new ArrayList<>();
            forEachWitnessInOrder((name, witnessValue) -> result.add(mapper.apply(name, witnessValue)));
            return result;
        }

        public <T> Map<String, T> mapWitnesses(BiFunction<String, SchnorrVariableValue, T> mapper) {
            HashMap<String, T> result = new HashMap<>();
            forEachWitnessInOrder((name, witnessValue) -> result.put(name, mapper.apply(name, witnessValue)));
            return result;
        }

        public void forEachWitnessInOrder(BiConsumer<String, SchnorrVariableValue> consumer) {
            witnessesForVariables.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEachOrdered(e -> consumer.accept(e.getKey(),e.getValue()));
        }

        public List<SchnorrVariableValue> getWitnessesInOrder() {
            return witnessesForVariables.entrySet().stream().sorted(Map.Entry.comparingByKey()).map(Map.Entry::getValue).collect(Collectors.toList());
        }
    }

    public static class SubprotocolSpecSecretBuilder {
        private final Map<String, SchnorrVariableValue> witnessesForVariables = new HashMap<>();
        private final Map<String, SecretInput> secretInputForSubprotocols = new HashMap<>();
        private final SubprotocolSpec spec;

        public SubprotocolSpecSecretBuilder(SubprotocolSpec spec) {
            this.spec = spec;
        }

        public SubprotocolSpecSecretBuilder putWitness(String variableName, SchnorrVariableValue witnessValue) {
            if (!spec.containsVariable(variableName))
                throw new IllegalArgumentException("Not a witness variable: "+variableName);

            witnessesForVariables.put(variableName, witnessValue);
            return this;
        }

        public SubprotocolSpecSecretBuilder putWitness(String variableName, Zn.ZnElement witnessValue) {
            return putWitness(variableName, new SchnorrZnVariableValue(witnessValue, (SchnorrZnVariable) spec.variables.get(variableName)));
        }

        public SubprotocolSpecSecretBuilder putWitness(String variableName, GroupElement witnessValue) {
            return putWitness(variableName, new SchnorrGroupElemVariableValue(witnessValue, (SchnorrGroupElemVariable) spec.variables.get(variableName)));
        }

        public SubprotocolSpecSecretBuilder putSubprotocolSecretInput(String subprotocolName, SecretInput secretInput) {
            if (!spec.containsSubprotocol(subprotocolName))
                throw new IllegalArgumentException("Not a subprotocol: "+subprotocolName);

            secretInputForSubprotocols.put(subprotocolName, secretInput);
            return this;
        }

        public SubprotocolSpecSecrets build() {
            spec.forEachVariable((name, var) -> {
                if (!witnessesForVariables.containsKey(name))
                    throw new IllegalStateException("Witness for " + name + "is missing");
            });

            spec.forEachProtocol((name, var) -> {
                if (!secretInputForSubprotocols.containsKey(name))
                    throw new IllegalStateException("Secret input for " + name + "is missing");
            });

            return new SubprotocolSpecSecrets(witnessesForVariables, secretInputForSubprotocols);
        }
    }
}
