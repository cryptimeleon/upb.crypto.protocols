package de.upb.crypto.clarc.protocols.arguments.sigma.schnorr;

import de.upb.crypto.clarc.protocols.arguments.sigma.schnorr.variables.SchnorrVariableAssignment;
import de.upb.crypto.math.serialization.Representation;

public abstract class DelegateFragment extends SendThenDelegateFragment {
    @Override
    protected ProverSpec provideProverSpec(SchnorrVariableAssignment outerWitnesses, ProverSpecBuilder builder) {
        builder.setSendFirstValue(SendFirstValue.EMPTY);
        return provideProverSpecWithNoSendFirst(outerWitnesses, builder);
    }

    protected abstract ProverSpec provideProverSpecWithNoSendFirst(SchnorrVariableAssignment outerWitnesses, ProverSpecBuilder builder);

    @Override
    protected SendFirstValue recreateSendFirstValue(Representation repr) {
        return SendFirstValue.EMPTY;
    }

    @Override
    protected SendFirstValue simulateSendFirstValue() {
        return SendFirstValue.EMPTY;
    }

    @Override
    protected SubprotocolSpec provideSubprotocolSpec(SendFirstValue sendFirstValue, SubprotocolSpecBuilder builder) {
        return provideSubprotocolSpec(builder);
    }

    protected abstract SubprotocolSpec provideSubprotocolSpec(SubprotocolSpecBuilder builder);

    @Override
    protected boolean provideAdditionalCheck(SendFirstValue sendFirstValue) {
        return true;
    }
}
