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

/**
 * Many Schnorr-style protocols have the following form:
 * <ol>
 *     <li>(Send) The prover generates some value and sends it to the verifier.</li>
 *     <li>(Delegate) Prover and verifier run a Sigma protocol depending on the value sent/received</li>
 * </ol>
 *
 * For example, a simple set membership proof works as follows (assuming some trusted party has published signatures on all valid set values):
 * <ol>
 *     <li>(Send) The prover sends a randomized signature on his secret value</li>
 *     <li>(Delegate) Prover and verifier run a Schnorr-style protocol for the statement "the prover can derandomize the signature such that it's a valid signature on his secret value"</li>
 * </ol>
 *
 * This class helps implement {@link SchnorrFragment}s with this Send-then-Delegate-to-Subfragments behavior.<br>
 * To implement a {@link SigmaProtocol} with this behavior, see {@link SendThenDelegateProtocol}. <br>
 * If your sendFirstValue is empty, consider using {@link DelegateFragment} or {@link DelegateProtocol}.
 */
public abstract class SendThenDelegateFragment implements SchnorrFragment {
    /**
     * <p>
     * Run by the prover to set up (1) the sendFirstValue and
     * (2) witness values for variables this fragment proves knowledge of itself (i.e. those specified in {@link SendThenDelegateFragment#provideSubprotocolSpec(SendFirstValue, SubprotocolSpecBuilder)}).
     * </p>
     * <p>
     * A typical example implementation can be found in {@link de.upb.crypto.clarc.protocols.arguments.sigma.schnorr.setmembership.SetMembershipFragment}.
     * </p>
     *
     * @param externalWitnesses the witness values for external variables
     * @param builder helper object to instantiate a {@link ProverSpec}
     * @return the specification of sendFirstValue and witness values for this fragment's own variables. Returned by {@link ProverSpecBuilder#build()}.
     */
    protected abstract ProverSpec provideProverSpec(SchnorrVariableAssignment externalWitnesses, ProverSpecBuilder builder);

    /**
     * Restores a sendFirstValue from {@link Representation}
     */
    protected abstract SendFirstValue recreateSendFirstValue(Representation repr);

    /**
     * Returns a random SendFirstValue with the same probability distribution as an honest prover would generate.
     */
    protected abstract SendFirstValue simulateSendFirstValue();

    /**
     * <p>
     * Run by both prover and verifier to deterministically instantiate the desired subprotocols (subfragments) depending on the sendFirstValue.<br>
     * For this, the given {@link SubprotocolSpecBuilder} allows you to create (1) variables (witnesses) and (2) register fragments to run.
     * The {@link SendThenDelegateFragment} will then take care of proving knowledge of the desired witnesses and running the desired subfragments.
     * For the subfragments, the registered variables will be considered "external" (cf. {@link SchnorrFragment}).
     * </p>
     * <p>
     * A typical example implementation can be found in {@link de.upb.crypto.clarc.protocols.arguments.sigma.schnorr.setmembership.SetMembershipFragment}.
     * </p>
     *
     * @param sendFirstValue the value the prover sends as his first message.
     * @param builder helper object to instantiate a {@link SubprotocolSpec}
     * @return the specification of what variables to prove knowledge of and what subfragments to run (for which these variables will be "external"). Returned by {@link SubprotocolSpecBuilder#build()}.
     */
    protected abstract SubprotocolSpec provideSubprotocolSpec(SendFirstValue sendFirstValue, SubprotocolSpecBuilder builder);

    /**
     * Runs an additional check on the sendFirstValue when the verifier checks a transcript.
     */
    protected abstract boolean provideAdditionalCheck(SendFirstValue sendFirstValue);

    @Override
    public AnnouncementSecret generateAnnouncementSecret(SchnorrVariableAssignment externalWitnesses) {
        //Ask implementing class for prover spec
        ProverSpec proverSpec = provideProverSpec(externalWitnesses, new ProverSpecBuilder(this));

        //Generate announcement secrets of subprotocols
        Map<String, AnnouncementSecret> subprotocolAnnouncementSecrets = proverSpec.subprotocolSpec.mapSubprotocols((name, subprotocol) ->
                subprotocol.generateAnnouncementSecret(proverSpec.witnesses.fallbackTo(externalWitnesses)));

        //Generate random assignment of knowledge variables
        SchnorrVariableValueList randomVariableValues = proverSpec.subprotocolSpec.createRandomVariableAssignment();

        return new SendThenDelegateAnnouncementSecret(randomVariableValues, proverSpec, subprotocolAnnouncementSecrets);
    }

    @Override
    public Announcement generateAnnouncement(SchnorrVariableAssignment externalWitnesses, AnnouncementSecret announcementSecret, SchnorrVariableAssignment externalRandom) {
        SendThenDelegateAnnouncementSecret announcementSecret1 = (SendThenDelegateAnnouncementSecret) announcementSecret;

        //For each subprotocol, generate its announcement.
        Map<String, Announcement> subprotocolAnnouncements = announcementSecret1.subprotocolSpec.mapSubprotocols(
                (name, fragment) -> fragment.generateAnnouncement(
                        announcementSecret1.witnessValues.fallbackTo(externalWitnesses),
                        announcementSecret1.subprotocolAnnouncementSecret.get(name),
                        announcementSecret1.randomVariableValues.fallbackTo(externalRandom)
                )
        );

        //Send sendFirstValue and subprotocolAnnouncements to verifier
        return new SendThenDelegateAnnouncement(announcementSecret1.subprotocolSpec, subprotocolAnnouncements, announcementSecret1.sendFirstValue);
    }

    @Override
    public Response generateResponse(SchnorrVariableAssignment externalWitnesses, AnnouncementSecret announcementSecret, SchnorrChallenge challenge) {
        SendThenDelegateAnnouncementSecret announcementSecret1 = (SendThenDelegateAnnouncementSecret) announcementSecret;
        WitnessValues witnessValues = announcementSecret1.witnessValues;

        //Generate subprotocol responses
        Map<String, Response> subprotocolResponses = announcementSecret1.subprotocolSpec.mapSubprotocols((subprotocolName, subprotocol) -> subprotocol.generateResponse(
                announcementSecret1.witnessValues.fallbackTo(externalWitnesses),
                announcementSecret1.subprotocolAnnouncementSecret.get(subprotocolName),
                challenge
        ));

        //challenge * witness + announcement for knowledge variables
        SchnorrVariableValueList knowledgeVarResponse = announcementSecret1.subprotocolSpec.createVariableAssignment((name, variable) ->
            witnessValues.getValue(variable).evalLinear(challenge.getChallenge(), announcementSecret1.randomVariableValues.getValue(variable))
        );

        return new SendThenDelegateResponse(subprotocolResponses, knowledgeVarResponse);
    }

    @Override
    public boolean checkTranscript(Announcement announcement, SchnorrChallenge challenge, Response response, SchnorrVariableAssignment externalResponse) {
        SendFirstValue sendFirstValue = ((SendThenDelegateAnnouncement) announcement).sendFirstValue;
        SubprotocolSpec subprotocolSpec = ((SendThenDelegateAnnouncement) announcement).subprotocolSpec;

        //Check that subprotocols accept
        try {
            subprotocolSpec.forEachProtocol((name, subprotocol) -> {
                if (!subprotocol.checkTranscript(
                            ((SendThenDelegateAnnouncement) announcement).subprotocolAnnouncements.get(name),
                            challenge,
                            ((SendThenDelegateResponse) response).subprotocolResponses.get(name),
                            ((SendThenDelegateResponse) response).variableResponses.fallbackTo(externalResponse)
                        )
                ) {
                    throw new RuntimeException("Subprotocol " + name + " does not accept its subtranscript");
                }
            });
        } catch (RuntimeException e) {
            System.err.println(e.getMessage());
            return false;
        }

        //Check additionalCheck on sendFirstValue
        if (!provideAdditionalCheck(sendFirstValue)) {
            System.err.println("Additional check on the sendFirstValue of "+this.getClass().getName()+" fails");
            return false;
        }
        return true;
    }

    @Override
    public SigmaProtocolTranscript generateSimulatedTranscript(SchnorrChallenge challenge, SchnorrVariableAssignment externalRandomResponse) {
        //Simulate sendFirstValue and set up subprotocols
        SendFirstValue sendFirstValue = simulateSendFirstValue();
        SubprotocolSpec subprotocolSpec = provideSubprotocolSpec(sendFirstValue, new SubprotocolSpecBuilder());

        //Simulate our own knowledge variables by choosing a random response for them
        SchnorrVariableValueList randomResponses = subprotocolSpec.createRandomVariableAssignment();

        //Ask subprotocols to simulate their transcripts
        Map<String, SigmaProtocolTranscript> subprotocolTranscripts = subprotocolSpec.mapSubprotocols((name, fragment) -> fragment.generateSimulatedTranscript(challenge, randomResponses.fallbackTo(externalRandomResponse)));

        //That's it. Collect what we have.
        HashMap<String, Announcement> subprotocolAnnouncements = new HashMap<>();
        HashMap<String, Response> subprotocolResponses = new HashMap<>();
        subprotocolTranscripts.forEach((name, transcript) -> {
            subprotocolAnnouncements.put(name, transcript.getAnnouncement());
            subprotocolResponses.put(name, transcript.getResponse());
        });

        return new SigmaProtocolTranscript(
                new SendThenDelegateAnnouncement(subprotocolSpec, subprotocolAnnouncements, sendFirstValue),
                challenge,
                new SendThenDelegateResponse(subprotocolResponses, randomResponses)
        );
    }

    @Override
    public Announcement recreateAnnouncement(Representation repr) {
        SendFirstValue sendFirstValue = recreateSendFirstValue(repr.list().get(0));
        SubprotocolSpec subprotocolSpec = provideSubprotocolSpec(sendFirstValue, new SubprotocolSpecBuilder());
        HashMap<String, Announcement> subprotocolAnnouncements = new HashMap<>();
        List<Map.Entry<String, SchnorrFragment>> subprotocolList = subprotocolSpec.getOrderedListOfSubprotocolsAndNames();

        for (int i=0;i<subprotocolList.size();i++)
            subprotocolAnnouncements.put(subprotocolList.get(i).getKey(), subprotocolList.get(i).getValue().recreateAnnouncement(repr.list().get(i+1)));

        return new SendThenDelegateAnnouncement(subprotocolSpec, subprotocolAnnouncements, sendFirstValue);
    }

    @Override
    public Response recreateResponse(Announcement announcement, Representation repr) {
        SubprotocolSpec subprotocolSpec = ((SendThenDelegateAnnouncement) announcement).subprotocolSpec;

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
        /**
         * An empty value to send first
         */
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

        @Override
        public int hashCode() {
            return 0;
        }

        @Override
        public boolean equals(Object obj) {
            return obj instanceof EmptySendFirstValue;
        }
    }

    /**
     * A list of algebraic values ({@link Element}s) to send first.
     */
    public static class AlgebraicSendFirstValue implements SendFirstValue {
        @UniqueByteRepresented
        private final List<Element> elements = new ArrayList<>();

        /**
         * Instantiates the SendFirstValue with an ordered list of values to send.
         */
        public AlgebraicSendFirstValue(Element... values) {
            elements.addAll(Arrays.asList(values));
        }

        /**
         * Recreates the SendFirstValue from representation.
         * @param repr the representation returned by {@link AlgebraicSendFirstValue#getRepresentation()}
         * @param structures the structures to use to recreate the sent elements (same order as in the {@link AlgebraicSendFirstValue(Element...)} constructor)
         */
        public AlgebraicSendFirstValue(Representation repr, Structure... structures) {
            for (int i=0;i<structures.length;i++)
                elements.add(structures[i].getElement(repr.list().get(i)));
        }

        /**
         * Returns the i'th element from the list (zero-based indexing)
         */
        public Element getElement(int i) {
            return elements.get(i);
        }

        /**
         * Returns the i'th element from the list (zero-based indexing)
         */
        public GroupElement getGroupElement(int i) {
            return (GroupElement) getElement(i);
        }

        /**
         * Returns the i'th element from the list (zero-based indexing)
         */
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

    private static class SendThenDelegateAnnouncementSecret implements AnnouncementSecret {
        public final SchnorrVariableAssignment randomVariableValues;
        public final ProverSpec proverSpec;
        public final Map<String, AnnouncementSecret> subprotocolAnnouncementSecret;
        public final SubprotocolSpec subprotocolSpec;
        public final SendFirstValue sendFirstValue;
        public final WitnessValues witnessValues;


        public SendThenDelegateAnnouncementSecret(SchnorrVariableAssignment randomVariableValues, ProverSpec proverSpec, Map<String, AnnouncementSecret> subprotocolAnnouncementSecret) {
            this.randomVariableValues = randomVariableValues;
            this.proverSpec = proverSpec;
            this.subprotocolAnnouncementSecret = subprotocolAnnouncementSecret;
            this.subprotocolSpec = proverSpec.subprotocolSpec;
            this.sendFirstValue = proverSpec.sendFirstValue;
            this.witnessValues = proverSpec.witnesses;
        }
    }

    private static class SendThenDelegateAnnouncement implements Announcement {
        @UniqueByteRepresented
        public final HashMap<String, Announcement> subprotocolAnnouncements = new HashMap<>();
        @UniqueByteRepresented
        public final SendFirstValue sendFirstValue;

        public final SubprotocolSpec subprotocolSpec;

        public SendThenDelegateAnnouncement(SubprotocolSpec subprotocolSpec, Map<String, ? extends Announcement> subprotocolAnnouncements, SendFirstValue sendFirstValue) {
            this.subprotocolSpec = subprotocolSpec;
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

    /**
     * Specifies what this Fragment shall do, i.e. what variables to prove knowledge of and what subprotocols to run.
     */
    public static class SubprotocolSpec {
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

    /**
     * A builder to help instantiate {@link SubprotocolSpec}s.
     */
    public static class SubprotocolSpecBuilder {
        private final HashMap<String, SchnorrFragment> subprotocols = new HashMap<>();
        private final HashMap<String, SchnorrVariable> variables = new HashMap<>();
        private boolean isBuilt = false;

        /**
         * Instantiate the {@link SubprotocolSpec} from the data provided.
         */
        public SubprotocolSpec build() {
            checkIsBuilt();
            isBuilt = true;
            return new SubprotocolSpec(subprotocols, variables);
        }

        /**
         * Specifies that the fragment shall prove knowledge of a {@link de.upb.crypto.math.structures.zn.Zn.ZnElement}.
         *
         * @param name name of the variable. Must be unique within this {@linkplain SubprotocolSpecBuilder}. The same names shall be used in {@link SendThenDelegateFragment#provideProverSpec(SchnorrVariableAssignment, ProverSpecBuilder)} when specifying a witness.
         * @param zn the ring that values of this variable belong to
         * @return a variable you can reference when constructing a {@link SchnorrFragment} subprotocol.
         */
        public SchnorrZnVariable addZnVariable(String name, Zn zn) {
            return addVariable(name, new SchnorrZnVariable(name, zn));
        }

        /**
         * Specifies that the fragment shall prove knowledge of a {@link GroupElement}.
         *
         * @param name name of the variable. Must be unique within this {@linkplain SubprotocolSpecBuilder}. The same names shall be used in {@link SendThenDelegateFragment#provideProverSpec(SchnorrVariableAssignment, ProverSpecBuilder)} when specifying a witness.
         * @param group the group that values of this variable belong to
         * @return a variable you can reference when constructing a {@link SchnorrFragment} subprotocol.
         */
        public SchnorrGroupElemVariable addGroupElemVariable(String name, Group group) {
            return addVariable(name, new SchnorrGroupElemVariable(name, group));
        }

        /**
         * Specifies that this fragment shall run the given subprotocol.
         *
         * @param name a name unique within this {@linkplain SubprotocolSpecBuilder}. You will not have to reference this name again.
         * @param fragment the subprotocol to be run.
         */
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

    /**
     * Helps build {@link ProverSpec} objects to describe data contributed by the prover.
     */
    public static class ProverSpecBuilder {
        private SendFirstValue sendFirstValue;
        private SubprotocolSpec subprotocolSpec;
        private final Map<String, SchnorrVariableValue> witnessesForVariables = new HashMap<>();
        private final Map<String, Zn.ZnElement> znWitnesses = new HashMap<>();
        private final Map<String, GroupElement> groupElemWitnesses = new HashMap<>();
        private boolean isBuilt = false;
        private final SendThenDelegateFragment fragment;

        /**
         * Construct the builder
         * @param fragment the fragment this builder is supposed to build a spec for.
         */
        public ProverSpecBuilder(SendThenDelegateFragment fragment) {
            this.fragment = fragment;
        }

        /**
         * Instructs the fragment to send the given value first to the verifier.
         */
        public void setSendFirstValue(SendFirstValue sendFirstValue) {
            if (this.sendFirstValue != null)
                throw new IllegalStateException("Cannot overwrite sendFirstValue");
            this.sendFirstValue = sendFirstValue;

            subprotocolSpec = fragment.provideSubprotocolSpec(sendFirstValue, new SubprotocolSpecBuilder());
        }

        /**
         * Instructs the fragment to use the given value for the witness variable registered via {@code addVariable()} in {@link SubprotocolSpecBuilder}.
         *
         * @param variableName the same name as used in {@code addVariable()}
         * @param witnessValue a value that (hopefully) makes the subprotocols accept their transcripts.
         */
        public void putWitnessValue(String variableName, Zn.ZnElement witnessValue) {
            checkDuplicate(variableName);
            znWitnesses.put(variableName, witnessValue);
        }

        /**
         * Instructs the fragment to use the given value for the witness variable registered via {@code addVariable()} in {@link SubprotocolSpecBuilder}.
         *
         * @param variableName the same name as used in {@code addVariable()}
         * @param witnessValue a value that (hopefully) makes the subprotocols accept their transcripts.
         */
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
                    throw new IllegalStateException("Variable "+name+" has not registered, but its witness has been given");
            });

            return new WitnessValues(witnessesForVariables);
        }

        public ProverSpec build() {
            if (isBuilt)
                throw new IllegalStateException("has already been built");
            isBuilt = true;
            if (sendFirstValue == null || subprotocolSpec == null)
                throw new IllegalStateException("sendFirstValue is not set or subprotocolSpec is null");
            return new ProverSpec(sendFirstValue, subprotocolSpec, buildWitnessValues());
        }
    }
}
