package de.upb.crypto.clarc.protocols.damgardtechnique;

import de.upb.crypto.clarc.protocols.CommonInput;
import de.upb.crypto.clarc.protocols.SecretInput;
import de.upb.crypto.clarc.protocols.arguments.InteractiveArgument;
import de.upb.crypto.clarc.protocols.arguments.InteractiveArgumentInstance;
import de.upb.crypto.clarc.protocols.arguments.sigma.Challenge;
import de.upb.crypto.clarc.protocols.arguments.sigma.SigmaProtocolInstance;
import de.upb.crypto.math.expressions.bool.BooleanExpression;
import de.upb.crypto.math.serialization.Representation;

public class DamgardInstance implements InteractiveArgumentInstance {
    protected DamgardTechnique protocol;
    protected SigmaProtocolInstance innerInstance;
    protected DamgardAnnouncement announcement;
    protected Challenge challenge;
    protected DamgardResponse response;
    protected int round;

    public DamgardInstance(String role, DamgardTechnique protocol, CommonInput commonInput, SecretInput secretInput) {
        this.protocol = protocol;
        this.innerInstance = (SigmaProtocolInstance) protocol.getInnerProtocol().instantiateProtocol(role, commonInput, secretInput);
        round = 0;
    }

    @Override
    public BooleanExpression getAcceptanceExpression() {
        //Check commitment in announcement
    }

    @Override
    public DamgardTechnique getProtocol() {
        return protocol;
    }

    @Override
    public String getRoleName() {
        return innerInstance.getRoleName();
    }

    @Override
    public Representation nextMessage(Representation received) {
        return null;
    }

    @Override
    public boolean hasTerminated() {
        return false;
    }
}
