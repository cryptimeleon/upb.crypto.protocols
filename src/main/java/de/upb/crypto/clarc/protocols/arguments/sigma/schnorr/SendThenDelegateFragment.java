package de.upb.crypto.clarc.protocols.arguments.sigma.schnorr;

import de.upb.crypto.clarc.protocols.arguments.sigma.*;
import de.upb.crypto.clarc.protocols.arguments.sigma.schnorr.variables.*;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.interfaces.structures.Element;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.interfaces.structures.Structure;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zn;

import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.stream.Collectors;

public abstract class SendThenDelegateFragment implements SchnorrFragment {
    protected abstract ProverSpec provideProverSpec(SchnorrVariableAssignment outerWitnesses);
    protected abstract SendFirstValue recreateSendFirstValue(Representation repr);
    protected abstract SendFirstValue simulateSendFirstValue();

    protected abstract SubprotocolSpec provideSubprotocolSpec(SendFirstValue sendFirstValue);

    protected abstract boolean provideAdditionalCheck(SendFirstValue sendFirstValue);

    @Override
    public AnnouncementSecret generateAnnouncementSecret(SchnorrVariableAssignment outerWitnesses) {
        //Ask implementing class for prover stuff
        ProverSpec proverSpec = provideProverSpec(outerWitnesses);

        //Generate announcement secrets
        HashMap<String, AnnouncementSecret> subprotocolAnnouncementSecrets = new HashMap<>();
        proverSpec.subprotocolSpec.mapSubprotocols((name, subprotocol) ->
                subprotocol.generateAnnouncementSecret(proverSpec.witnesses.fallbackTo(outerWitnesses)));

        //Generate random assignment of knowledge variables
        SchnorrVariableValueList randomVariableValues = proverSpec.subprotocolSpec.createRandomVariableAssignment();

        return new SendThenDelegateAnnouncementSecret(randomVariableValues, proverSpec, subprotocolAnnouncementSecrets);
    }

    @Override
    public Announcement generateAnnouncement(SchnorrVariableAssignment outerWitnesses, AnnouncementSecret announcementSecret, SchnorrVariableAssignment outerRandom) {
        SendThenDelegateAnnouncementSecret announcementSecret1 = (SendThenDelegateAnnouncementSecret) announcementSecret;

        Map<String, Announcement> subprotocolAnnouncements = announcementSecret1.subprotocolSpec.mapSubprotocols(
                (name, fragment) -> fragment.generateAnnouncement(
                        announcementSecret1.witnessValues.fallbackTo(outerWitnesses),
                        announcementSecret1.subprotocolAnnouncementSecret.get(name),
                        announcementSecret1.randomVariableValues.fallbackTo(outerRandom)
                )
        );

        return new SendThenDelegateAnnouncement(subprotocolAnnouncements, announcementSecret1.sendFirstValue);
    }

    @Override
    public Response generateResponse(SchnorrVariableAssignment outerWitnesses, AnnouncementSecret announcementSecret, Challenge challenge) {
        SendThenDelegateAnnouncementSecret announcementSecret1 = (SendThenDelegateAnnouncementSecret) announcementSecret;
        WitnessValues witnessValues = announcementSecret1.witnessValues;

        //Subprotocol responses
        Map<String, Response> subprotocolResponses = announcementSecret1.subprotocolSpec.mapSubprotocols((subprotocolName, subprotocol) -> subprotocol.generateResponse(
                announcementSecret1.witnessValues.fallbackTo(outerWitnesses),
                announcementSecret1.subprotocolAnnouncementSecret.get(subprotocolName),
                challenge
        ));

        //challenge * witness + announcement for knowledge variables
        SchnorrVariableValueList knowledgeVarResponse = announcementSecret1.subprotocolSpec.createVariableAssignment((name, variable) ->
            witnessValues.getValue(variable).evalLinear(((SchnorrChallenge) challenge).getChallenge(), announcementSecret1.randomVariableValues.getValue(variable))
        );

        return new SendThenDelegateResponse(subprotocolResponses, knowledgeVarResponse);
    }

    @Override
    public boolean checkTranscript(Announcement announcement, Challenge challenge, Response response, SchnorrVariableAssignment outerResponse) {
        SendFirstValue sendFirstValue = ((SendThenDelegateAnnouncement) announcement).sendFirstValue;
        SubprotocolSpec subprotocolSpec = provideSubprotocolSpec(sendFirstValue);

        //Check that subprotocol accept
        try {
            subprotocolSpec.forEachProtocol((name, subprotocol) -> {
                if (!subprotocol.checkTranscript(
                            ((SendThenDelegateAnnouncement) announcement).subprotocolAnnouncements.get(name),
                            challenge,
                            ((SendThenDelegateResponse) response).subprotocolResponses.get(name),
                            ((SendThenDelegateResponse) response).variableResponses.fallbackTo(outerResponse)
                        )
                ) {
                    throw new RuntimeException("Subprotocol " + name + " does not accept its subtranscript");
                }
            });
        } catch (RuntimeException e) {
            System.err.println(e.getMessage());
            return false;
        }

        if (!provideAdditionalCheck(sendFirstValue)) {
            System.err.println("Additional check on the sendFirstValue of "+this.getClass().getName()+" fails");
            return false;
        }
        return true;
    }

    @Override
    public SigmaProtocolTranscript generateSimulatedTranscript(Challenge challenge, SchnorrVariableAssignment outerRandomResponse) {
        SendFirstValue sendFirstValue = simulateSendFirstValue();
        SubprotocolSpec subprotocolSpec = provideSubprotocolSpec(sendFirstValue);

        //Simulate our own knowledge variables by choosing a random response for them
        SchnorrVariableValueList randomResponses = subprotocolSpec.createRandomVariableAssignment();

        //Ask subprotocols to simulate their transcripts
        Map<String, SigmaProtocolTranscript> subprotocolTranscripts = subprotocolSpec.mapSubprotocols((name, fragment) -> fragment.generateSimulatedTranscript(challenge, randomResponses.fallbackTo(outerRandomResponse)));

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

        return new SendThenDelegateAnnouncement(subprotocolAnnouncements, sendFirstValue); //TODO might as well cache subprotocolSpec and sendFirstValue in the announcement so that we don't have to call provideSubprotocolSpec() so often...
    }

    @Override
    public Response recreateResponse(Announcement announcement, Representation repr) {
        SendFirstValue sendFirstValue = ((SendThenDelegateAnnouncement) announcement).sendFirstValue;
        SubprotocolSpec subprotocolSpec = provideSubprotocolSpec(sendFirstValue);

        SchnorrVariableValueList variableResponses = new SchnorrVariableValueList(subprotocolSpec.getOrderedListOfVariables(), repr.list().get(0));

        Map<String, Response> subprotocolResponses = new HashMap<>();

        List<Map.Entry<String, SchnorrFragment>> subprotocols = subprotocolSpec.getOrderedListOfSubprotocolsAndNames();
        for (int i=0;i<subprotocols.size();i++) {
            String name = subprotocols.get(i).getKey();
            SchnorrFragment subprotocol = subprotocols.get(i).getValue();
            subprotocolResponses.put(name, subprotocol.recreateResponse(((SendThenDelegateAnnouncement) announcement).subprotocolAnnouncements.get(name), repr.list().get(i+1)));
        }

        return new SendThenDelegateResponse(subprotocolResponses, variableResponses);
    }

    public interface SendFirstValue extends Representable, UniqueByteRepresentable {
        SendFirstValue EMPTY = new EmptySendFirstValue();
    }

    private static class EmptySendFirstValue implements SendFirstValue {
        @Override
        public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
            return accumulator;
        }

        @Override
        public Representation getRepresentation() {
            return new ObjectRepresentation();
        }
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
        public final SchnorrVariableAssignment randomVariableValues;
        public final ProverSpec proverSpec;
        public final HashMap<String, AnnouncementSecret> subprotocolAnnouncementSecret;
        public final SubprotocolSpec subprotocolSpec;
        public final SendFirstValue sendFirstValue;
        public final WitnessValues witnessValues;


        public SendThenDelegateAnnouncementSecret(SchnorrVariableAssignment randomVariableValues, ProverSpec proverSpec, HashMap<String, AnnouncementSecret> subprotocolAnnouncementSecret) {
            this.randomVariableValues = randomVariableValues;
            this.proverSpec = proverSpec;
            this.subprotocolAnnouncementSecret = subprotocolAnnouncementSecret;
            this.subprotocolSpec = proverSpec.subprotocolSpec;
            this.sendFirstValue = proverSpec.sendFirstValue;
            this.witnessValues = proverSpec.witnesses;
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
        private final Map<String, Response> subprotocolResponses;
        @UniqueByteRepresented
        private final SchnorrVariableValueList variableResponses;

        public SendThenDelegateResponse(Map<String, Response> subprotocolResponses, SchnorrVariableValueList variableResponses) {
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

    protected static class SubprotocolSpec {
        private final Map<String, SchnorrFragment> subprotocols;
        private final Map<String, SchnorrVariable> variables;

        private SubprotocolSpec(Map<String, SchnorrFragment> subprotocols, Map<String, SchnorrVariable> variables) {
            this.subprotocols = subprotocols;
            this.variables = variables;
        }

        public SchnorrVariableValueList createVariableAssignment(BiFunction<String, SchnorrVariable, SchnorrVariableValue> mapper) {
            return new SchnorrVariableValueList(
                variables.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .map(entry -> mapper.apply(entry.getKey(), entry.getValue()))
                    .collect(Collectors.toList())
            );
        }

        public SchnorrVariableValueList createRandomVariableAssignment() {
            return createVariableAssignment((k,v) -> v.generateRandomValue());
        }

        public <T> Map<String, T> mapSubprotocols(BiFunction<String, SchnorrFragment, T> mapper) {
            HashMap<String, T> result = new HashMap<>();
            subprotocols.forEach((name, subprotocol) -> result.put(name, mapper.apply(name, subprotocol)));
            return result;
        }

        public void forEachVariable(BiConsumer<String, SchnorrVariable> consumer) {
            variables.forEach(consumer);
        }

        public void forEachProtocol(BiConsumer<String, SchnorrFragment> consumer) {
            subprotocols.forEach(consumer);
        }

        public List<Map.Entry<String, SchnorrFragment>> getOrderedListOfSubprotocolsAndNames() {
            return subprotocols.entrySet().stream().sorted(Map.Entry.comparingByKey()).collect(Collectors.toList());
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

        public SchnorrVariable getVariable(String variableName) {
            return variables.get(variableName);
        }
    }

    public static class SubprotocolSpecBuilder {
        private final HashMap<String, SchnorrFragment> subprotocols = new HashMap<>();
        private final HashMap<String, SchnorrVariable> variables = new HashMap<>();
        private boolean isBuilt = false;

        public SubprotocolSpec build() {
            checkIsBuilt();
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

    public static class WitnessValues extends SchnorrVariableValueList {
        private WitnessValues(Map<String, SchnorrVariableValue> witnessesForVariables) {
            super(witnessesForVariables);
        }
    }

    public static class ProverSpec {
        public final SendFirstValue sendFirstValue;
        public final SubprotocolSpec subprotocolSpec;
        public final WitnessValues witnesses;

        private ProverSpec(SendFirstValue sendFirstValue, SubprotocolSpec subprotocolSpec, WitnessValues witnesses) {
            this.sendFirstValue = sendFirstValue;
            this.subprotocolSpec = subprotocolSpec;
            this.witnesses = witnesses;
        }
    }

    public class ProverSpecBuilder {
        private SendFirstValue sendFirstValue;
        private SubprotocolSpec subprotocolSpec;
        private final Map<String, SchnorrVariableValue> witnessesForVariables = new HashMap<>();
        private final Map<String, Zn.ZnElement> znWitnesses = new HashMap<>();
        private final Map<String, GroupElement> groupElemWitnesses = new HashMap<>();
        private boolean isBuilt = false;

        public void setSendFirstValue(SendFirstValue sendFirstValue) {
            if (this.sendFirstValue != null)
                throw new IllegalStateException("Cannot overwrite sendFirstValue");
            this.sendFirstValue = sendFirstValue;

            subprotocolSpec = provideSubprotocolSpec(sendFirstValue);
        }

        public SubprotocolSpec getSubprotocolSpec() {
            return subprotocolSpec;
        }

        public void putWitnessValue(String variableName, SchnorrVariableValue witnessValue) {
            checkDuplicate(variableName);
            witnessesForVariables.put(variableName, witnessValue);
        }

        public void putWitnessValue(String variableName, Zn.ZnElement witnessValue) {
            checkDuplicate(variableName);
            znWitnesses.put(variableName, witnessValue);
        }

        public void putWitnessValue(String variableName, GroupElement witnessValue) {
            checkDuplicate(variableName);
            groupElemWitnesses.put(variableName, witnessValue);
        }

        private void checkDuplicate(String name) {
            if (witnessesForVariables.containsKey(name) || znWitnesses.containsKey(name) || groupElemWitnesses.containsKey(name))
                throw new IllegalArgumentException("Witness "+name+" is already registered.");
        }

        private WitnessValues buildWitnessValues() {
            //Populate the witnessForVariables map with znWitnesses and groupElemWitnesses (not possible earlier because user may have added variables by name before subprotocolSpec has been set up with the concrete SchnorrVariable objects)
            znWitnesses.forEach((name, val) -> witnessesForVariables.put(name, new SchnorrZnVariableValue(val, (SchnorrZnVariable) subprotocolSpec.getVariable(name))));
            groupElemWitnesses.forEach((name, val) -> witnessesForVariables.put(name, new SchnorrGroupElemVariableValue(val, (SchnorrGroupElemVariable) subprotocolSpec.getVariable(name))));

            subprotocolSpec.forEachVariable((name, var) -> {
                if (!witnessesForVariables.containsKey(name))
                    throw new IllegalStateException("Witness for " + name + "is missing");
            });

            witnessesForVariables.forEach((name, val) -> {
                if (!subprotocolSpec.containsVariable(val.getVariable()))
                    throw new IllegalStateException("");
            });

            return new WitnessValues(witnessesForVariables);
        }

        public WitnessValues getWitnessValues() {
            return buildWitnessValues();
        }

        public ProverSpec build() {
            if (isBuilt)
                throw new IllegalStateException("has already been built");
            isBuilt = true;
            if (sendFirstValue == null || subprotocolSpec == null)
                throw new IllegalStateException("sendFirstValue is not set or subprotocolSpec is null");
            return new ProverSpec(sendFirstValue, subprotocolSpec, getWitnessValues());
        }
    }
}
