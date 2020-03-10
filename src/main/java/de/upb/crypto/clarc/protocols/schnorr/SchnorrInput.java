package de.upb.crypto.clarc.protocols.schnorr;

import de.upb.crypto.clarc.protocols.CommonInput;
import de.upb.crypto.clarc.protocols.SecretInput;
import de.upb.crypto.clarc.protocols.schnorr.stmts.api.SchnorrStatementInput;
import de.upb.crypto.math.expressions.ValueBundle;

import java.util.HashMap;

/**
 * The input to a Schnorr protocol is a bundle of algebraic values (ValueBundle).
 * Additionally, optionally, each statement of the Schnorr proof can have private input.
 */
public class SchnorrInput extends ValueBundle implements CommonInput, SecretInput {
    private HashMap<String, SchnorrStatementInput> privateStatementInput = new HashMap<>();

    public void putPrivateStatementInput(String statementName, SchnorrStatementInput input) {
        privateStatementInput.put(statementName, input);
    }

    public SchnorrStatementInput getPrivateStatementInput(String statementName) {
        return privateStatementInput.get(statementName);
    }
}
