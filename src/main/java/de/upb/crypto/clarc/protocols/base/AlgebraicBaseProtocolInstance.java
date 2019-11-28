package de.upb.crypto.clarc.protocols.base;

import de.upb.crypto.clarc.protocols.TwoPartyProtocol;
import de.upb.crypto.clarc.protocols.TwoPartyProtocolInstance;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;

import java.util.HashMap;

public abstract class AlgebraicBaseProtocolInstance implements TwoPartyProtocolInstance, AlgebraicVariableContext {
    static final String HIGH_LEVEL_PROT_MSGS = "high_level_prot_msgs";

    private AlgebraicBaseProtocol protocol;
    private String role;
    protected int round = 0;
    private HashMap<String, TwoPartyProtocolInstance> newSubprotocolInstances = new HashMap<>();
    private HashMap<String, TwoPartyProtocolInstance> runningSubprotocolInstances = new HashMap<>();
    private HashMap<String, Representation> valuesToSendNext = new HashMap<>();
    private HashMap<String, Representation> valuesReceived = new HashMap<>();
    /**
     * A util for this object.
     */
    private ReprUtil reprUtil = new ReprUtil(this);
    private boolean highLevelWantsTerminate = false;

    public AlgebraicBaseProtocolInstance(AlgebraicBaseProtocol protocol, String role) {
        this.protocol = protocol;
        this.role = role;
        this.round = this.sendsFirstMessage() ? 0 : 1;
    }

    @Override
    public TwoPartyProtocol getProtocol() {
        return protocol;
    }

    protected void runSubprotocolConcurrently(String instanceName, TwoPartyProtocolInstance instance) {
        newSubprotocolInstances.put(instanceName, instance);
    }

    protected void send(String id) {
        Representation repr = reprUtil.serializeSingleField(id);
        valuesToSendNext.put(id, repr);
    }

    protected void receive(String id) {
        reprUtil.deserializeSingleField(id, valuesReceived.get(id));
        valuesReceived.remove(id); //done with that.
    }

    protected void terminate() {
        this.highLevelWantsTerminate = true;
    }

    @Override
    public Representation nextMessage(Representation received) {
        ObjectRepresentation toSend = new ObjectRepresentation();

        //High-level protocol receiving (send()/receive() methods)
        received.obj().get(HIGH_LEVEL_PROT_MSGS).obj().forEach(e -> valuesReceived.put(e.getKey(), e.getValue()));

        //Advance subprotocols
        runningSubprotocolInstances.forEach( (name, instance) -> {
            Representation nextMsg = instance.nextMessage(received.obj().get(name));
            if (nextMsg != null)
                toSend.put(name, nextMsg);
        });

        //Call user-defined function for this round
        if (role.equals(getProtocol().getFirstMessageRole()))
            doRoundForFirstRole(round);
        else
            doRoundForSecondRole(round);
        round += 2;

        //High-level protocol sending (send()/receive() methods)
        ObjectRepresentation high_level_prot_msgs = new ObjectRepresentation();
        valuesToSendNext.forEach(high_level_prot_msgs::put);
        valuesToSendNext = new HashMap<>();
        toSend.put(HIGH_LEVEL_PROT_MSGS, high_level_prot_msgs);

        //Subprotocol handling for newly added sub-protocols
        newSubprotocolInstances.forEach((name, instance) -> {
            if (instance.sendsFirstMessage())
                toSend.put(name, instance.nextMessage(null));
            else {
                Representation nextMsg = instance.nextMessage(received.obj().get(name));
                if (nextMsg != null)
                    toSend.put(name, nextMsg);
            }
            runningSubprotocolInstances.put(name, instance);
        });
        newSubprotocolInstances = new HashMap<>();

        //Housekeeping
        runningSubprotocolInstances.entrySet().removeIf(e -> e.getValue().hasTerminated()); //remove protocols we're done with.

        return toSend;
    }

    protected abstract void doRoundForFirstRole(int round);
    protected abstract void doRoundForSecondRole(int round);

    @Override
    public boolean hasTerminated() {
        return this.highLevelWantsTerminate && runningSubprotocolInstances.isEmpty();
    }
}
