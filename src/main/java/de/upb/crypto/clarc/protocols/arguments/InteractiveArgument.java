package de.upb.crypto.clarc.protocols.arguments;

import de.upb.crypto.clarc.protocols.CommonInput;
import de.upb.crypto.clarc.protocols.SecretInput;
import de.upb.crypto.clarc.protocols.TwoPartyProtocol;

/**
 * An argument, i.e. a two-party protocol with roles "prover" and "verifier"
 */
public interface InteractiveArgument extends TwoPartyProtocol {
    String PROVER_ROLE = "prover";
    String VERIFIER_ROLE = "verifier";

    @Override
    default String[] getRoleNames() {
        return new String[]{"prover", "verifier"};
    }

    @Override
    InteractiveArgumentInstance instantiateProtocol(String role, CommonInput commonInput, SecretInput secretInput);

    default InteractiveArgumentInstance instantiateProver(CommonInput commonInput, SecretInput witness) {
        return instantiateProtocol(PROVER_ROLE, commonInput, witness);
    }

    default InteractiveArgumentInstance instantiateVerifier(CommonInput commonInput) {
        return instantiateProtocol(VERIFIER_ROLE, commonInput, null);
    }
}
